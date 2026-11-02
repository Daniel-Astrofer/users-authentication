package com.kerosene.auth.application.orchestrator.passkey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import com.kerosene.auth.application.infra.persistence.jpa.PasskeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.PasskeyVerificationProjection;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.orchestrator.login.StartLogin;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.orchestrator.signup.port.SignupStateStore;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy;
import com.kerosene.auth.application.service.devicebinding.DeviceCredentialReplayGuard;
import com.kerosene.auth.application.service.passkey.PasskeyInventoryService;
import com.kerosene.auth.application.service.passkey.PasskeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.PasskeyActionRequiredDTO;
import com.kerosene.auth.dto.SignupState;
import com.kerosene.auth.dto.passkey.PasskeyRegistrationRequest;
import com.kerosene.auth.dto.passkey.PasskeyVerifyRequest;
import com.kerosene.auth.model.entity.PasskeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.common.exception.ErrorCodes;
import com.kerosene.common.infra.logging.LogDomain;
import com.kerosene.common.infra.logging.LogSanitizer;
import com.kerosene.common.exception.FinancialProviderUnavailableException;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/** Orchestrates WebAuthn passkey enrollment, login, replay protection, and onboarding completion. */
@Service
public class PasskeyOrchestrator {

    /** Logger for passkey operational events; identity and credential references are sanitized. */
    private static final Logger log = LoggerFactory.getLogger(PasskeyOrchestrator.class);
    /** Authentication log marker used for security-sensitive onboarding events. */
    private static final org.slf4j.Marker AUTH_MARKER = org.slf4j.MarkerFactory.getMarker("AUTH");

    /** WebAuthn protocol operations for challenges, signatures, origins, and authenticator data. */
    private final PasskeyService passkeyService;
    /** Credential lookup, persistence, and monotonic counter advancement repository. */
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    /** Account lookup used to resolve passkey owners. */
    private final UserRepository userRepository;
    /** JWT issuer for passkey-authenticated or newly created accounts. */
    private final JwtServicer jwtServicer;
    /** Temporary signup session state used during onboarding registration. */
    private final SignupStateStore signupStateStore;
    /** Inventory and client-action guidance for unusable credentials. */
    private final PasskeyInventoryService passkeyInventoryService;
    /** Signup finalizer and account financial-readiness operation. */
    private final FinalizeSignupAccount finalizeSignupAccount;
    /** Temporary pre-authentication storage used when TOTP remains required. */
    private final RedisServicer redisService;
    /** Device-installation ownership checks and unlink transaction policy. */
    private final DeviceBindingPolicy deviceBindingPolicy;
    /** Replay-failure tracking and temporary credential lock policy. */
    private final DeviceCredentialReplayGuard deviceCredentialReplayGuard;
    /** Isolated transaction boundary for credential write operations. */
    private final TransactionTemplate transactionTemplate;

    /**
     * Creates the orchestrator and a transaction template for isolated credential writes.
     * @param passkeyService WebAuthn protocol operations
     * @param passkeyCredentialRepository credential persistence and counter updates
     * @param userRepository account lookup
     * @param jwtServicer session token issuer
     * @param signupStateStore pending signup state
     * @param passkeyInventoryService inventory and action guidance service
     * @param finalizeSignupAccount signup finalizer
     * @param redisService temporary authentication state storage
     * @param deviceBindingPolicy installation ownership policy
     * @param deviceCredentialReplayGuard replay failure and lock policy
     * @param transactionManager database transaction manager
     */
    public PasskeyOrchestrator(
            PasskeyService passkeyService,
            PasskeyCredentialRepository passkeyCredentialRepository,
            UserRepository userRepository,
            JwtServicer jwtServicer,
            SignupStateStore signupStateStore,
            PasskeyInventoryService passkeyInventoryService,
            FinalizeSignupAccount finalizeSignupAccount,
            RedisServicer redisService,
            DeviceBindingPolicy deviceBindingPolicy,
            DeviceCredentialReplayGuard deviceCredentialReplayGuard,
            PlatformTransactionManager transactionManager) {
        this.passkeyService = passkeyService;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.userRepository = userRepository;
        this.jwtServicer = jwtServicer;
        this.signupStateStore = signupStateStore;
        this.passkeyInventoryService = passkeyInventoryService;
        this.finalizeSignupAccount = finalizeSignupAccount;
        this.redisService = redisService;
        this.deviceBindingPolicy = deviceBindingPolicy;
        this.deviceCredentialReplayGuard = deviceCredentialReplayGuard;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /**
     * Not fully transactional: binding conflict is resolved in REQUIRES_NEW TXs so AUTH_024
     * never poisons the caller's transaction (UnexpectedRollbackException → HTTP 500).
     * @param userId authenticated account identifier
     * @param request registration proof and device metadata
     * @return HTTP response describing success or registration failure
     */
    public ResponseEntity<ApiResponse<?>> registerPasskey(Long userId, PasskeyRegistrationRequest request) {
        try {
            UserDataBase user = userRepository.findById(userId).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.error("User not found", ErrorCodes.AUTH_USER_NOT_FOUND));
            }

            ResponseEntity<ApiResponse<?>> invalidOrigin = rejectInvalidPasskeyOrigin(
                    user.getUsername(), request.getClientDataJSON());
            if (invalidOrigin != null) {
                return invalidOrigin;
            }

            // Binding probe before consuming the challenge so clients can retry after confirm.
            if (!request.isConfirmUnlinkDevice()) {
                var probe = deviceBindingPolicy.findBindingConflict(
                        request.getDeviceInstallId(), user.getId());
                if (probe != null) {
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                            .body(ApiResponse.error(
                                    probe.message(),
                                    ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                                    probe));
                }
            }

            String consumedChallenge = passkeyService.consumeChallengeFromRedis(user.getUsername());
            if (consumedChallenge == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                        ApiResponse.error("Registration challenge expired or invalid. Request a new one first.",
                                ErrorCodes.AUTH_PASSKEY_CHALLENGE));
            }

            byte[] pkToVerify;
            java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
            try {
                pkToVerify = decoder.decode(request.getPublicKeyCose());
            } catch (Exception e) {
                pkToVerify = java.util.Base64.getUrlDecoder().decode(request.getPublicKeyCose());
            }

            if (request.getSignature() == null || !passkeyService.verifyRegistrationSignature(
                    user.getUsername(),
                    consumedChallenge,
                    request.getSignature(),
                    pkToVerify,
                    request.getAuthData(),
                    request.getClientDataJSON())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.error("Proof of possession failed: Invalid signature or challenge",
                                "INVALID_SIGNATURE"));
            }

            var bindingConflict = deviceBindingPolicy.ensureDeviceAvailableForBind(
                    request.getDeviceInstallId(),
                    user.getId(),
                    request.isConfirmUnlinkDevice());
            if (bindingConflict != null) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponse.error(
                                bindingConflict.message(),
                                ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                                bindingConflict));
            }

            final java.util.Base64.Decoder decoderForSave = decoder;
            final byte[] publicKeyForSave = pkToVerify;
            return transactionTemplate.execute(status ->
                    persistRegisteredPasskey(user, request, publicKeyForSave, decoderForSave));
        } catch (Exception e) {
            log.error("Failed to register passkey", e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Passkey registration failed.", ErrorCodes.AUTH_GENERIC));
        }
    }

    /** Persists a verified credential and its decoded identity, context, and device metadata. */
    /** @param user existing credential owner */
    /** @param request registration request already verified against the challenge */
    /** @param pkToVerify decoded public COSE key */
    /** @param decoder Base64 decoder selected for identifier data */
    /** @return successful registration response */
    private ResponseEntity<ApiResponse<?>> persistRegisteredPasskey(
            UserDataBase user,
            PasskeyRegistrationRequest request,
            byte[] pkToVerify,
            java.util.Base64.Decoder decoder) {
        PasskeyCredential credential = new PasskeyCredential();
        credential.setPublicKeyCose(pkToVerify);

        try {
            if (request.getCredentialId() != null) {
                credential.setCredentialId(decoder.decode(request.getCredentialId()));
            }
            if (request.getUserHandle() != null) {
                credential.setUserHandle(decoder.decode(request.getUserHandle()));
            }
        } catch (IllegalArgumentException e) {
            decoder = java.util.Base64.getUrlDecoder();
            if (request.getCredentialId() != null) {
                credential.setCredentialId(decoder.decode(request.getCredentialId()));
            }
            if (request.getUserHandle() != null) {
                credential.setUserHandle(decoder.decode(request.getUserHandle()));
            }
        }
        if (credential.getUserHandle() == null && credential.getCredentialId() != null) {
            credential.setUserHandle(credential.getCredentialId());
        }

        credential.setDeviceName(request.getDeviceName());
        applyPasskeyContextMetadata(credential, request);
        applyPasskeyDeviceMetadata(credential, request);
        credential.setUser(user);
        credential.setSignatureCount(passkeyService.extractSignatureCount(request.getAuthData()));

        passkeyCredentialRepository.save(credential);
        return ResponseEntity.ok(ApiResponse.success("Passkey registered successfully", "OK"));
    }

    /**
     * Resolves the owner and credential, consumes and verifies the challenge, advances the replay
     * counter, then returns TOTP continuation or a session token.
     * @param request submitted WebAuthn assertion
     * @return authentication result, challenge requirement, or actionable failure response
     */
    @Transactional
    public ResponseEntity<ApiResponse<Object>> verifyAndLogin(PasskeyVerifyRequest request) {
        byte[] credentialIdBytes = null;
        try {
            String normalizedUsername = normalizeUsername(request.getUsername());
            if (request.getCredentialId() == null) {
                logVerifyFailure(
                        "missing_credential_id",
                        "MISSING_CREDENTIAL_ID",
                        request,
                        normalizedUsername,
                        null,
                        null,
                        null,
                        null);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                        ApiResponse.error("Frontend must send the credentialId for secure lookup.",
                                "MISSING_CREDENTIAL_ID"));
            }

            try {
                credentialIdBytes = java.util.Base64.getUrlDecoder().decode(request.getCredentialId());
            } catch (Exception e) {
                credentialIdBytes = java.util.Base64.getDecoder().decode(request.getCredentialId());
            }

            UserDataBase user;
            Optional<PasskeyVerificationProjection> credOpt;
            if (normalizedUsername.isBlank()) {
                credOpt = passkeyCredentialRepository.findVerificationByCredentialId(credentialIdBytes);
                if (credOpt.isEmpty() || credOpt.get().userId() == null) {
                    logVerifyFailure(
                            "credential_unlinked",
                            ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                            request,
                            normalizedUsername,
                            credentialIdBytes,
                            credOpt.orElse(null),
                            null,
                            null);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(ApiResponse.error(
                                    "A passkey enviada nao esta vinculada a nenhuma conta.",
                                    ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND));
                }
                user = userRepository.findById(credOpt.get().userId()).orElse(null);
                if (user == null) {
                    logVerifyFailure(
                            "credential_user_missing",
                            ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                            request,
                            normalizedUsername,
                            credentialIdBytes,
                            credOpt.get(),
                            null,
                            null);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(ApiResponse.error("Passkey credential user no longer exists.",
                                    ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND));
                }
                normalizedUsername = normalizeUsername(user.getUsername());
            } else {
                user = userRepository.findByUsername(normalizedUsername);
                if (user == null) {
                    logVerifyFailure(
                            "user_not_found",
                            ErrorCodes.AUTH_USER_NOT_FOUND,
                            request,
                            normalizedUsername,
                            credentialIdBytes,
                            null,
                            null,
                            null);
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(ApiResponse.error("User not found", ErrorCodes.AUTH_USER_NOT_FOUND));
                }
                credOpt = passkeyCredentialRepository.findVerificationByCredentialIdAndUserId(credentialIdBytes, user.getId());
            }

            if (credOpt.isEmpty()) {
                logVerifyFailure(
                        "credential_not_found",
                        ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        null,
                        null,
                        null);
                return passkeyLinkRequired(
                        user,
                        HttpStatus.UNAUTHORIZED,
                        ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                        "A passkey enviada nao esta vinculada a esta conta.",
                        "Entre com senha + TOTP e vincule uma nova passkey para este dispositivo.");
            }

            PasskeyVerificationProjection cred = credOpt.get();
            if (!isActiveCredential(cred.status())) {
                logVerifyFailure(
                        "credential_inactive",
                        ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        null);
                return passkeyLinkRequired(
                        user,
                        HttpStatus.UNAUTHORIZED,
                        ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND,
                        "Este dispositivo autenticado foi bloqueado ou revogado.",
                        "Revise os dispositivos autenticados no app antes de tentar novamente.");
            }
            if (passkeyInventoryService.isKnownIncompatibleForCurrentLogin(cred.relyingPartyId(), cred.originHost())) {
                logVerifyFailure(
                        "credential_incompatible",
                        ErrorCodes.AUTH_PASSKEY_LINK_REQUIRED,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        null);
                return passkeyLinkRequired(
                        user,
                        HttpStatus.CONFLICT,
                        ErrorCodes.AUTH_PASSKEY_LINK_REQUIRED,
                        "Esta passkey foi vinculada a outro login/origem e nao pode autenticar aqui.",
                        "Entre com senha + TOTP e vincule uma nova passkey compativel com este dispositivo.");
            }

            ResponseEntity<ApiResponse<?>> invalidOrigin = rejectInvalidPasskeyOrigin(
                    normalizedUsername, request.getClientDataJSON());
            if (invalidOrigin != null) {
                logVerifyFailure(
                        "invalid_origin",
                        ErrorCodes.AUTH_PASSKEY_INVALID_ORIGIN,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        null);
                @SuppressWarnings("unchecked")
                ResponseEntity<ApiResponse<Object>> cast = (ResponseEntity<ApiResponse<Object>>) (ResponseEntity<?>) invalidOrigin;
                return cast;
            }

            String credentialRefEarly = DeviceCredentialReplayGuard.credentialRefFromBytes(credentialIdBytes);
            if (deviceCredentialReplayGuard.isLocked(user.getId(), credentialRefEarly)) {
                logVerifyFailure(
                        "replay_soft_lock_active",
                        ErrorCodes.AUTH_DEVICE_CRED_REPLAY_LOCKED,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        null);
                return passkeyReplayLocked(user);
            }

            String consumedChallenge = passkeyService.consumeChallengeFromRedis(normalizedUsername);
            if (consumedChallenge == null) {
                String renewedChallenge = passkeyService.generateChallenge(normalizedUsername);
                logVerifyFailure(
                        "challenge_missing",
                        ErrorCodes.AUTH_PASSKEY_CHALLENGE,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        null);
                return ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED)
                        .body(ApiResponse.error(
                                "PASSKEY_CHALLENGE_REQUIRED:" + renewedChallenge,
                                ErrorCodes.AUTH_PASSKEY_CHALLENGE,
                                passkeyInventoryService.buildChallengeRequired(
                                        user,
                                        renewedChallenge,
                                        "O challenge da passkey expirou. Assine um novo challenge para continuar.")));
            }

            PasskeyService.PasskeyVerificationResult verification = passkeyService.verifyAuthenticationAssertion(
                    normalizedUsername,
                    consumedChallenge,
                    request.getSignature(),
                    cred.publicKeyCose(),
                    request.getAuthData(),
                    request.getClientDataJSON());

            if (verification.verified()) {
                String credentialRef = DeviceCredentialReplayGuard.credentialRefFromBytes(credentialIdBytes);
                long newSignatureCount = verification.signatureCount();
                if (newSignatureCount <= cred.signatureCount()) {
                    logVerifyFailure(
                            "replay_counter_not_advanced",
                            ErrorCodes.AUTH_PASSKEY_REPLAY,
                            request,
                            normalizedUsername,
                            credentialIdBytes,
                            cred,
                            cred.signatureCount(),
                            newSignatureCount);
                    return passkeyReplayConflict(user, credentialRef);
                }
                int updated = passkeyCredentialRepository.advanceSignatureCount(
                        cred.credentialId(),
                        user.getId(),
                        newSignatureCount);
                if (updated != 1) {
                    logVerifyFailure(
                            "replay_counter_update_rejected",
                            ErrorCodes.AUTH_PASSKEY_REPLAY,
                            request,
                            normalizedUsername,
                            credentialIdBytes,
                            cred,
                            cred.signatureCount(),
                            newSignatureCount);
                    return passkeyReplayConflict(user, credentialRef);
                }
                deviceCredentialReplayGuard.clearFailures(user.getId(), credentialRef);

                finalizeSignupAccount.ensureUserFinancialsReady(user, null);

                if (!Boolean.TRUE.equals(user.getIsActive())) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(ApiResponse.error("Account is inactive", ErrorCodes.AUTH_INVALID_CREDENTIALS));
                }

                if (user.hasTotpEnabled()) {
                    String preAuthToken = UUID.randomUUID().toString();
                    redisService.setValue(StartLogin.preAuthKey(preAuthToken), user.getUsername(), StartLogin.PRE_AUTH_TTL_SECONDS);
                    return ResponseEntity.status(HttpStatus.ACCEPTED)
                            .body(ApiResponse.success("Passkey verified. TOTP required.", preAuthToken));
                }

                String token = user.getId() + " " + jwtServicer.generateTokenAtCredentialEpoch(user.getId(), java.util.List.of("USER"), user.getCredentialEpoch());
                return ResponseEntity.ok(ApiResponse.success("Passkey authentication successful", token));
            } else {
                logVerifyFailure(
                        "assertion_failed",
                        ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED,
                        request,
                        normalizedUsername,
                        credentialIdBytes,
                        cred,
                        null,
                        verification.signatureCount());
                return passkeyLinkRequired(
                        user,
                        HttpStatus.UNAUTHORIZED,
                        ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED,
                        "A assinatura da passkey ou o challenge foram rejeitados.",
                        "Se esta passkey nao estiver disponivel neste dispositivo, entre com TOTP e vincule outra.");
            }

        } catch (FinancialProviderUnavailableException
                 | FinalizeSignupAccount.VaultNotReadyException exception) {
            throw exception;
        } catch (Exception e) {
            logVerifyFailure(
                    "exception",
                    ErrorCodes.AUTH_GENERIC,
                    request,
                    request == null ? "" : normalizeUsername(request.getUsername()),
                    credentialIdBytes,
                    null,
                    null,
                    null);
            log.error("Passkey verification failed", e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Passkey verification failed.", ErrorCodes.AUTH_GENERIC));
        }
    }

    /**
     * Binding conflict / challenge verification happen outside a single write TX so AUTH_024
     * cannot surface as UnexpectedRollbackException (HTTP 500) to the mobile client.
     * @param sessionId pending signup session identifier
     * @param request registration proof and device metadata
     * @return account-created response or a typed failure response
     */
    public ResponseEntity<ApiResponse<?>> finishOnboardingRegistration(String sessionId, PasskeyRegistrationRequest request) {
        SignupState state = signupStateStore.findSignupState(sessionId);
        if (state == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Session expired", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        ResponseEntity<ApiResponse<?>> invalidOrigin = rejectInvalidPasskeyOrigin(
                state.getUsername(), request.getClientDataJSON());
        if (invalidOrigin != null) {
            return invalidOrigin;
        }

        // Probe before consuming challenge: client can re-sign after user confirms unlink.
        if (!request.isConfirmUnlinkDevice()) {
            var probe = deviceBindingPolicy.findBindingConflict(request.getDeviceInstallId(), null);
            if (probe != null) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponse.error(
                                probe.message(),
                                ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                                probe));
            }
        }

        String challenge = passkeyService.consumeChallengeFromRedis(state.getUsername());
        if (challenge == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Registration challenge expired or invalid", ErrorCodes.AUTH_PASSKEY_CHALLENGE));
        }

        byte[] pkToVerify;
        if (request.getPublicKeyCose() != null) {
            try {
                pkToVerify = java.util.Base64.getDecoder().decode(request.getPublicKeyCose());
            } catch (Exception e) {
                pkToVerify = java.util.Base64.getUrlDecoder().decode(request.getPublicKeyCose());
            }
        } else {
            try {
                pkToVerify = java.util.Base64.getDecoder().decode(request.getPublicKey());
            } catch (Exception e) {
                pkToVerify = java.util.Base64.getUrlDecoder().decode(request.getPublicKey());
            }
        }

        if (request.getSignature() == null || !passkeyService.verifyRegistrationSignature(
                state.getUsername(),
                challenge,
                request.getSignature(),
                pkToVerify,
                request.getAuthData(),
                request.getClientDataJSON())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Proof of possession failed: Invalid signature or challenge",
                            "INVALID_SIGNATURE"));
        }

        // REQUIRES_NEW: unlink/write for binding stays isolated from finalizeSignupAccount TX.
        var bindingConflict = deviceBindingPolicy.ensureDeviceAvailableForBind(
                request.getDeviceInstallId(),
                null,
                request.isConfirmUnlinkDevice());
        if (bindingConflict != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.error(
                            bindingConflict.message(),
                            ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                            bindingConflict));
        }

        state.setPasskeyPublicKey(request.getPublicKey());
        state.setPasskeyDeviceName(request.getDeviceName());
        state.setPasskeyCredentialId(request.getCredentialId());
        state.setPasskeyUserHandle(request.getUserHandle());
        state.setPasskeyPublicKeyCose(request.getPublicKeyCose());
        state.setPasskeyRelyingPartyId(resolveRelyingPartyIdFromProof(request));
        state.setPasskeyOriginHost(passkeyService.extractOriginHostFromClientData(request.getClientDataJSON()));
        state.setPasskeyBrand(request.getBrand());
        state.setPasskeyModel(request.getModel());
        state.setPasskeySerialNumber(request.getSerialNumber());
        state.setPasskeyDeviceInstallId(request.getDeviceInstallId());
        state.setPasskeyPlatform(request.getPlatform());
        state.setPasskeyBrowser(request.getBrowser());
        state.setPasskeyRegistered(true);

        UserDataBase user;
        try {
            signupStateStore.saveSignupState(sessionId, state, Duration.ofMinutes(1440));
            user = finalizeSignupAccount.execute(sessionId);
        } catch (FinancialProviderUnavailableException
                 | FinalizeSignupAccount.VaultNotReadyException exception) {
            log.warn(AUTH_MARKER, "Passkey onboarding finalization is temporarily unavailable for sessionRef={} userRef={}: {}",
                    LogSanitizer.fingerprint(sessionId),
                    LogSanitizer.fingerprint(state.getUsername()),
                    exception.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(ApiResponse.error(
                            "Account creation is temporarily unavailable. " + exception.getMessage(),
                            ErrorCodes.VAULT_STORAGE_ERROR));
        } catch (RuntimeException exception) {
            log.error(AUTH_MARKER, "Passkey onboarding finalization failed for sessionRef={} userRef={}: {} - {}",
                    LogSanitizer.fingerprint(sessionId),
                    LogSanitizer.fingerprint(state.getUsername()),
                    exception.getClass().getSimpleName(),
                    exception.getMessage(),
                    exception);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(ApiResponse.error(
                            "Account creation failed: " + exception.getMessage(),
                            ErrorCodes.SYS_INTERNAL_ERROR));
        }
        String token = user.getId() + " " + jwtServicer.generateTokenAtCredentialEpoch(user.getId(), java.util.List.of("USER"), user.getCredentialEpoch());
        return ResponseEntity.ok(ApiResponse.success(
                "Passkey linked and account created.",
                token));
    }

    /** Rejects origins outside the configured allowlist and logs only fingerprinted identity data. */
    /** @param username username associated with the request */
    /** @param clientDataJSON encoded WebAuthn client data containing the origin */
    /** @return unauthorized response when invalid, otherwise {@code null} */
    private ResponseEntity<ApiResponse<?>> rejectInvalidPasskeyOrigin(String username, String clientDataJSON) {
        if (passkeyService.isClientDataOriginAllowed(clientDataJSON)) {
            return null;
        }

        log.warn("Rejected passkey clientData origin for userRef={} originRef={}",
                LogSanitizer.fingerprint(username),
                LogSanitizer.fingerprint(passkeyService.extractOriginFromClientData(clientDataJSON)));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(
                        "Passkey origin is not allowed for this app build.",
                ErrorCodes.AUTH_PASSKEY_INVALID_ORIGIN));
    }

    /** Trims and lowercases with a locale-independent rule; null becomes the empty string. */
    /** @param username submitted username */
    /** @return normalized username */
    private String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    /** Builds the client recovery response requesting a passkey compatible with this login. */
    /** @param user account requiring a replacement or newly linked passkey */
    /** @param status HTTP status associated with the failed attempt */
    /** @param errorCode stable API error code */
    /** @param message public failure message */
    /** @param reason recovery instruction shown to the client */
    /** @return response with structured passkey-link guidance */
    private ResponseEntity<ApiResponse<Object>> passkeyLinkRequired(
            UserDataBase user,
            HttpStatus status,
            String errorCode,
            String message,
            String reason) {
        PasskeyActionRequiredDTO data = passkeyInventoryService.buildLinkNewPasskeyGuidance(user, reason);
        return ResponseEntity.status(status).body(ApiResponse.error(message, errorCode, data));
    }

    /** Tracks a counter conflict and returns retry guidance or an active-lock response. */
    /** @param user account whose credential failed replay validation */
    /** @param credentialRef sanitized credential reference */
    /** @return replay rejection or locked response */
    private ResponseEntity<ApiResponse<Object>> passkeyReplayConflict(UserDataBase user, String credentialRef) {
        boolean locked = deviceCredentialReplayGuard.recordReplayFailure(
                user.getId(),
                credentialRef,
                "PASSKEY");
        if (locked) {
            return passkeyReplayLocked(user);
        }
        PasskeyActionRequiredDTO data = passkeyInventoryService.buildReplayConflictGuidance(
                user,
                "Possivel conflito de seguranca no contador da chave. Tente novamente; "
                        + "nao e necessario vincular outra chave neste passo.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(
                        "O contador do autenticador nao avancou; esta chave foi rejeitada.",
                        ErrorCodes.AUTH_PASSKEY_REPLAY,
                        data));
    }

    /** Builds a locked response containing the replay guard's configured wait guidance. */
    /** @param user account whose credential is temporarily locked */
    /** @return HTTP 423 response */
    private ResponseEntity<ApiResponse<Object>> passkeyReplayLocked(UserDataBase user) {
        PasskeyActionRequiredDTO data = passkeyInventoryService.buildReplayLockedGuidance(
                user,
                deviceCredentialReplayGuard.lockSeconds());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(ApiResponse.error(
                        "Chave do dispositivo temporariamente bloqueada por possivel conflito de seguranca.",
                        ErrorCodes.AUTH_DEVICE_CRED_REPLAY_LOCKED,
                        data));
    }

    /** Logs a failed branch using sanitized identity, credential, origin, and counter references. */
    /** @param failureBranch internal verification branch label */
    /** @param errorCode associated API error code */
    /** @param request assertion request, possibly absent on error paths */
    /** @param normalizedUsername canonical username for fingerprinting */
    /** @param credentialIdBytes decoded credential ID when available */
    /** @param credential persisted verification projection when available */
    /** @param storedSignatureCount previously persisted counter */
    /** @param receivedSignatureCount counter received in the assertion */
    private void logVerifyFailure(
            String failureBranch,
            String errorCode,
            PasskeyVerifyRequest request,
            String normalizedUsername,
            byte[] credentialIdBytes,
            PasskeyVerificationProjection credential,
            Long storedSignatureCount,
            Long receivedSignatureCount) {
        log.warn(
                LogDomain.AUTH,
                "event=AUTH_PASSKEY_VERIFY_FAILED failureBranch={} errorCode={} usernamePresent={} credentialIdPresent={} credentialRef={} userRef={} savedRpIdRef={} savedOriginHost={} currentRpId={} currentHost={} storedSignatureCount={} receivedSignatureCount={}",
                failureBranch,
                errorCode,
                request != null && hasText(request.getUsername()),
                request != null && hasText(request.getCredentialId()),
                credentialRef(request, credentialIdBytes),
                LogSanitizer.fingerprint(normalizedUsername),
                credential == null ? "absent" : LogSanitizer.fingerprint(credential.relyingPartyId()),
                credential == null ? "absent" : safeLogMetadata(credential.originHost()),
                safeLogMetadata(resolveCurrentRelyingPartyIdForLog()),
                safeLogMetadata(resolveCurrentRequestHostForLog()),
                storedSignatureCount == null ? "n/a" : storedSignatureCount,
                receivedSignatureCount == null ? "n/a" : receivedSignatureCount);
    }

    /** Fingerprints decoded credential bytes or encoded request data for diagnostics. */
    /** @param request request that may contain an encoded credential ID */
    /** @param credentialIdBytes decoded credential ID when parsing succeeded */
    /** @return sanitized reference, or {@code absent} */
    private String credentialRef(PasskeyVerifyRequest request, byte[] credentialIdBytes) {
        if (credentialIdBytes != null && credentialIdBytes.length > 0) {
            return LogSanitizer.fingerprint(credentialIdBytes);
        }
        if (request == null || !hasText(request.getCredentialId())) {
            return "absent";
        }
        return LogSanitizer.fingerprint(request.getCredentialId());
    }

    /** Resolves the current RP ID for diagnostics, returning a bounded marker if resolution fails. */
    /** @return current RP ID or {@code unavailable} */
    private String resolveCurrentRelyingPartyIdForLog() {
        try {
            return passkeyService.resolveCurrentRelyingPartyId();
        } catch (RuntimeException exception) {
            return "unavailable";
        }
    }

    /** Resolves the request host for diagnostics, returning a bounded marker if resolution fails. */
    /** @return current request host or {@code unavailable} */
    private String resolveCurrentRequestHostForLog() {
        try {
            return passkeyService.resolveCurrentRequestHost();
        } catch (RuntimeException exception) {
            return "unavailable";
        }
    }

    /** Sanitizes log metadata and fingerprints values longer than the logging bound. */
    /** @param value candidate metadata */
    /** @return sanitized bounded text, fingerprint, or {@code absent} */
    private String safeLogMetadata(String value) {
        if (!hasText(value)) {
            return "absent";
        }
        String sanitized = LogSanitizer.sanitizeFinancialPayload(value.trim());
        if (!hasText(sanitized)) {
            return "absent";
        }
        return sanitized.length() > 128 ? LogSanitizer.fingerprint(sanitized) : sanitized;
    }

    /** Copies the proof-derived relying-party ID and origin host into the credential. */
    /** @param credential credential being prepared for persistence */
    /** @param request verified registration proof and client data */
    private void applyPasskeyContextMetadata(PasskeyCredential credential, PasskeyRegistrationRequest request) {
        credential.setRelyingPartyId(resolveRelyingPartyIdFromProof(request));
        credential.setOriginHost(passkeyService.extractOriginHostFromClientData(request.getClientDataJSON()));
    }

    /** Resolves the RP ID from authenticator proof, falling back to the client-data RP claim. */
    /** @param request registration request carrying proof and client data */
    /** @return first non-blank resolved RP ID, or {@code null} */
    private String resolveRelyingPartyIdFromProof(PasskeyRegistrationRequest request) {
        String matchedRpId = passkeyService.resolveRelyingPartyIdFromAuthenticatorData(
                request.getAuthData(),
                request.getClientDataJSON());
        return firstNonBlank(
                matchedRpId,
                passkeyService.resolveRelyingPartyIdFromClientData(request.getClientDataJSON()));
    }

    /** Copies device metadata from registration and defaults an absent status to ACTIVE. */
    /** @param credential credential entity to populate */
    /** @param request submitted device metadata */
    private void applyPasskeyDeviceMetadata(PasskeyCredential credential, PasskeyRegistrationRequest request) {
        credential.setBrand(request.getBrand());
        credential.setModel(request.getModel());
        credential.setSerialNumber(request.getSerialNumber());
        credential.setDeviceInstallId(request.getDeviceInstallId());
        credential.setPlatform(request.getPlatform());
        credential.setBrowser(request.getBrowser());
        credential.setStatus(firstNonBlank(request.getStatus(), "ACTIVE"));
    }

    /** Returns trimmed text or a fallback when the candidate is null or blank. */
    /** @param value candidate text */
    /** @param fallback substitute text */
    /** @return trimmed candidate or fallback */
    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    /** Treats legacy absent status as active and explicit ACTIVE as active case-insensitively. */
    /** @param status persisted credential status */
    /** @return whether the credential is eligible for authentication */
    private boolean isActiveCredential(String status) {
        return status == null || status.isBlank() || "ACTIVE".equalsIgnoreCase(status);
    }

    /** Checks whether text is non-null and contains a non-whitespace character. */
    /** @param value candidate text */
    /** @return true when the value is not blank */
    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
