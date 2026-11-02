package com.kerosene.auth.application.usecase.devicekey;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.orchestrator.login.StartLogin;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/** Verifies a device-key assertion, advances its replay counter, then authenticates or starts TOTP. */
@Component
public class VerifyDeviceKeyLoginUseCase {

    /** Verifies signatures and protocol claims for device-key authentication. */
    private final DeviceKeyService deviceKeyService;
    /** Looks up credentials and atomically advances their monotonic counters. */
    private final DeviceKeyCredentialRepository deviceKeyRepository;
    /** Resolves the account by normalized username when supplied by the request. */
    private final UserRepository userRepository;
    /** Ensures financial account prerequisites are available before login succeeds. */
    private final FinalizeSignupAccount finalizeSignupAccount;
    /** Issues the authenticated account's JWT. */
    private final JwtServicer jwtServicer;
    /** Stores short-lived pre-authentication state when the account requires TOTP. */
    private final RedisServicer redisService;

    /** Creates the device-key login verification operation. */
    /** @param deviceKeyService signature and challenge verifier */
    /** @param deviceKeyRepository credential lookup and counter update repository */
    /** @param userRepository account lookup repository */
    /** @param finalizeSignupAccount account readiness operation */
    /** @param jwtServicer session token issuer */
    /** @param redisService temporary pre-authentication storage */
    public VerifyDeviceKeyLoginUseCase(
            DeviceKeyService deviceKeyService,
            DeviceKeyCredentialRepository deviceKeyRepository,
            UserRepository userRepository,
            FinalizeSignupAccount finalizeSignupAccount,
            JwtServicer jwtServicer,
            RedisServicer redisService) {
        this.deviceKeyService = deviceKeyService;
        this.deviceKeyRepository = deviceKeyRepository;
        this.userRepository = userRepository;
        this.finalizeSignupAccount = finalizeSignupAccount;
        this.jwtServicer = jwtServicer;
        this.redisService = redisService;
    }

    /**
     * Resolves the credential owner, verifies the assertion, persists the advanced counter, checks
     * account readiness/activity, then returns a session token or a TOTP pre-auth token.
     *
     * @param request submitted assertion, credential identifier, and optional username
     * @return typed authentication outcome and optional token data
     */
    @Transactional
    public Result execute(DeviceKeyVerifyRequest request) {
        if (request.getCredentialId() == null || request.getCredentialId().isBlank()) {
            return Result.invalidCredentialId();
        }

        UserDataBase user;
        Optional<DeviceKeyCredential> credentialOpt;
        String credentialId = request.getCredentialId().trim();
        String normalizedUsername = DeviceKeyUsernameSupport.normalizeUsername(request.getUsername());
        if (normalizedUsername.isBlank()) {
            credentialOpt = deviceKeyRepository.findByCredentialId(credentialId);
            if (credentialOpt.isEmpty()) {
                return Result.credentialNotFound();
            }
            user = credentialOpt.get().getUser();
        } else {
            user = userRepository.findByUsername(normalizedUsername);
            if (user == null) {
                return Result.userNotFound();
            }
            credentialOpt = deviceKeyRepository.findByCredentialIdAndUserId(credentialId, user.getId());
        }

        if (credentialOpt.isEmpty()) {
            return Result.credentialNotFound();
        }

        DeviceKeyCredential credential = credentialOpt.get();
        long newCounter = deviceKeyService.verifyAuthentication(request, user, credential);
        int updated = deviceKeyRepository.advanceCounter(
                credential.getCredentialId(),
                user.getId(),
                newCounter,
                LocalDateTime.now());
        if (updated != 1) {
            return Result.replayCounterNotAdvanced();
        }

        finalizeSignupAccount.ensureUserFinancialsReady(user, null);

        if (!Boolean.TRUE.equals(user.getIsActive())) {
            return Result.inactiveAccount();
        }

        if (user.hasTotpEnabled()) {
            String preAuthToken = UUID.randomUUID().toString();
            redisService.setValue(StartLogin.preAuthKey(preAuthToken), user.getUsername(), StartLogin.PRE_AUTH_TTL_SECONDS);
            return Result.totpRequired(preAuthToken);
        }

        String token = user.getId() + " " + jwtServicer.generateTokenAtCredentialEpoch(user.getId(), java.util.List.of("USER"), user.getCredentialEpoch());
        return Result.authenticated(token);
    }

    /**
     * Result of device-key authentication; data holds a token when further authentication is needed.
     * @param status outcome of input, lookup, replay-counter, account, and factor checks
     * @param data pre-auth token for {@link Status#TOTP_REQUIRED}, session response for {@link Status#AUTHENTICATED}, otherwise null
     */
    public record Result(Status status, Object data) {

        /** Creates the invalid-credential-ID outcome. */
        /** @return invalid ID result */
        public static Result invalidCredentialId() {
            return new Result(Status.INVALID_CREDENTIAL_ID, null);
        }

        /** Creates the credential-not-found outcome. */
        /** @return missing credential result */
        public static Result credentialNotFound() {
            return new Result(Status.CREDENTIAL_NOT_FOUND, null);
        }

        /** Creates the user-not-found outcome. */
        /** @return missing user result */
        public static Result userNotFound() {
            return new Result(Status.USER_NOT_FOUND, null);
        }

        /** Creates the outcome used when the stored replay counter could not be advanced. */
        /** @return replay-counter failure result */
        public static Result replayCounterNotAdvanced() {
            return new Result(Status.REPLAY_COUNTER_NOT_ADVANCED, null);
        }

        /** Creates the inactive-account outcome after a valid assertion. */
        /** @return inactive account result */
        public static Result inactiveAccount() {
            return new Result(Status.INACTIVE_ACCOUNT, null);
        }

        /** Creates the result that requires the client to complete TOTP. */
        /** @param preAuthToken short-lived token for the TOTP continuation */
        /** @return TOTP-required result */
        public static Result totpRequired(String preAuthToken) {
            return new Result(Status.TOTP_REQUIRED, preAuthToken);
        }

        /** Creates the authenticated result carrying the session response. */
        /** @param token legacy user-ID and JWT response string */
        /** @return authenticated result */
        public static Result authenticated(String token) {
            return new Result(Status.AUTHENTICATED, token);
        }
    }

    /** Outcomes of device-key login verification and account checks. */
    public enum Status {
        /** Request omitted or blanked the credential identifier. */
        INVALID_CREDENTIAL_ID,
        /** No credential matched the identifier and selected owner. */
        CREDENTIAL_NOT_FOUND,
        /** No account matched the supplied normalized username. */
        USER_NOT_FOUND,
        /** Atomic persistence rejected the counter advancement, preventing replay acceptance. */
        REPLAY_COUNTER_NOT_ADVANCED,
        /** Credential assertion was valid but the account is inactive. */
        INACTIVE_ACCOUNT,
        /** Account requires the normal TOTP continuation before session issuance. */
        TOTP_REQUIRED,
        /** Authentication completed and a session token was issued. */
        AUTHENTICATED
    }
}
