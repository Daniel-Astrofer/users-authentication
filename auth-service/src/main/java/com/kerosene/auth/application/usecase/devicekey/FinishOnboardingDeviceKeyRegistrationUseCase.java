package com.kerosene.auth.application.usecase.devicekey;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.orchestrator.signup.port.SignupStateStore;
import com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.SignupState;
import com.kerosene.auth.dto.devicebinding.DeviceAlreadyBoundDTO;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

import java.time.Duration;

/** Verifies an onboarding device-key response, finalizes signup, binds the device, and issues a session. */
@Component
public class FinishOnboardingDeviceKeyRegistrationUseCase {

    /** Signup-state lifetime refreshed to retain registration flags until finalization. */
    private static final Duration SIGNUP_STATE_TTL = Duration.ofMinutes(1440);

    /** Temporary signup-state boundary. */
    private final SignupStateStore signupStateStore;
    /** Verifies the device-key registration challenge and attestation data. */
    private final DeviceKeyService deviceKeyService;
    /** Creates the persisted user account from validated signup state. */
    private final FinalizeSignupAccount finalizeSignupAccount;
    /** Device-key credential persistence used after successful verification and binding checks. */
    private final DeviceKeyCredentialRepository deviceKeyRepository;
    /** Issues the JWT for the newly created account. */
    private final JwtServicer jwtServicer;
    /** Prevents a device installation already owned elsewhere from being silently rebound. */
    private final DeviceBindingPolicy deviceBindingPolicy;

    /**
     * Creates the onboarding completion operation.
     *
     * @param signupStateStore temporary signup-state port
     * @param deviceKeyService challenge verification service
     * @param finalizeSignupAccount account creation operation
     * @param deviceKeyRepository credential persistence repository
     * @param jwtServicer session token issuer
     * @param deviceBindingPolicy installation ownership policy
     */
    public FinishOnboardingDeviceKeyRegistrationUseCase(
            SignupStateStore signupStateStore,
            DeviceKeyService deviceKeyService,
            FinalizeSignupAccount finalizeSignupAccount,
            DeviceKeyCredentialRepository deviceKeyRepository,
            JwtServicer jwtServicer,
            DeviceBindingPolicy deviceBindingPolicy) {
        this.signupStateStore = signupStateStore;
        this.deviceKeyService = deviceKeyService;
        this.finalizeSignupAccount = finalizeSignupAccount;
        this.deviceKeyRepository = deviceKeyRepository;
        this.jwtServicer = jwtServicer;
        this.deviceBindingPolicy = deviceBindingPolicy;
    }

    /**
     * Verifies the response against signup state, checks installation ownership, sets registration
     * flags, finalizes the account, persists its credential, and returns a session token.
     *
     * @param sessionId signup session that owns the outstanding challenge
     * @param request submitted device-key registration response and device metadata
     * @return created session, expired-session result, or binding-conflict payload
     */
    @Transactional
    public Result execute(String sessionId, DeviceKeyRegistrationRequest request) {
        SignupState state = signupStateStore.findSignupState(sessionId);
        if (state == null) {
            return Result.sessionExpired();
        }

        DeviceKeyService.VerifiedDeviceKeyRegistration verified =
                deviceKeyService.verifyRegistration(request, sessionId, state.getUsername());

        var bindingConflict = deviceBindingPolicy.ensureDeviceAvailableForBind(
                verified.deviceInstallId(),
                null,
                request.isConfirmUnlinkDevice());
        if (bindingConflict != null) {
            return Result.deviceAlreadyBound(bindingConflict);
        }

        state.setDeviceKeyRegistered(true);
        state.setPasskeyRegistered(true);
        signupStateStore.saveSignupState(sessionId, state, SIGNUP_STATE_TTL);

        UserDataBase user = finalizeSignupAccount.execute(sessionId);
        persistDeviceKey(user, verified);

        String token = user.getId() + " " + jwtServicer.generateTokenAtCredentialEpoch(user.getId(), java.util.List.of("USER"), user.getCredentialEpoch());
        return Result.created(token);
    }

    /**
     * Persists the verified public credential when it is not already stored for this user.
     * @param user newly finalized owner of the credential
     * @param verified cryptographically verified registration material and device metadata
     */
    private void persistDeviceKey(
            UserDataBase user,
            DeviceKeyService.VerifiedDeviceKeyRegistration verified) {
        if (deviceKeyRepository.findByCredentialIdAndUserId(verified.credentialId(), user.getId()).isPresent()) {
            return;
        }

        DeviceKeyCredential credential = new DeviceKeyCredential();
        credential.setUser(user);
        credential.setCredentialId(verified.credentialId());
        credential.setUserHandle(verified.userHandle());
        credential.setPublicKeyEd25519(verified.publicKeyEd25519());
        credential.setAlgorithm(DeviceKeyService.ALGORITHM);
        credential.setCounter(verified.counter());
        credential.setDeviceName(verified.deviceName());
        credential.setDeviceInstallId(verified.deviceInstallId());
        credential.setKeyStorage(verified.keyStorage());
        credential.setPlatform(verified.platform());
        credential.setBrowser(verified.browser());
        credential.setBrand(verified.brand());
        credential.setModel(verified.model());
        credential.setSerialNumber(verified.serialNumber());
        credential.setOnionServiceId(verified.onionServiceId());
        credential.setProtocolVersion(1);
        credential.setStatus("ACTIVE");
        deviceKeyRepository.save(credential);
    }

    /**
     * Result of completing device-key registration during onboarding.
     * @param status outcome of signup state, binding check, and account creation
     * @param token authenticated response token, present only for {@link Status#CREATED}
     * @param deviceAlreadyBound conflict details, present only for {@link Status#DEVICE_ALREADY_BOUND}
     */
    public record Result(Status status, String token, DeviceAlreadyBoundDTO deviceAlreadyBound) {

        /**
         * Builds the result containing the new account's session token.
         * @param token legacy user-ID and JWT response string
         * @return created result
         */
        public static Result created(String token) {
            return new Result(Status.CREATED, token, null);
        }

        /**
         * Builds the result for missing or expired signup state.
         * @return expired-session result without token or conflict payload
         */
        public static Result sessionExpired() {
            return new Result(Status.SESSION_EXPIRED, null, null);
        }

        /**
         * Builds the result carrying device installation ownership conflict details.
         * @param payload conflict information for the client confirmation flow
         * @return device-bound conflict result
         */
        public static Result deviceAlreadyBound(DeviceAlreadyBoundDTO payload) {
            return new Result(Status.DEVICE_ALREADY_BOUND, null, payload);
        }
    }

    /** Possible outcomes when finishing onboarding device-key registration. */
    public enum Status {
        /** Account and credential were created and a session token was issued. */
        CREATED,
        /** Signup state was absent or expired before verification. */
        SESSION_EXPIRED,
        /** Device installation is already bound and requires explicit conflict handling. */
        DEVICE_ALREADY_BOUND
    }
}
