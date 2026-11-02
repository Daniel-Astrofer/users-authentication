package com.kerosene.auth.application.usecase.devicekey;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.dto.devicebinding.DeviceAlreadyBoundDTO;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

/** Verifies and persists a new device-key credential for an existing authenticated account. */
@Component
public class FinishAuthenticatedDeviceKeyRegistrationUseCase {

    /** User lookup for the authenticated credential owner. */
    private final UserRepository userRepository;
    /** Device-key credential persistence repository. */
    private final DeviceKeyCredentialRepository deviceKeyRepository;
    /** Verifies registration proof and extracts trusted public credential metadata. */
    private final DeviceKeyService deviceKeyService;
    /** Checks existing device-installation ownership before saving a new credential. */
    private final DeviceBindingPolicy deviceBindingPolicy;

    /**
     * Creates the authenticated registration completion operation.
     * @param userRepository owner lookup
     * @param deviceKeyRepository credential persistence
     * @param deviceKeyService challenge response verifier
     * @param deviceBindingPolicy device-installation ownership policy
     */
    public FinishAuthenticatedDeviceKeyRegistrationUseCase(
            UserRepository userRepository,
            DeviceKeyCredentialRepository deviceKeyRepository,
            DeviceKeyService deviceKeyService,
            DeviceBindingPolicy deviceBindingPolicy) {
        this.userRepository = userRepository;
        this.deviceKeyRepository = deviceKeyRepository;
        this.deviceKeyService = deviceKeyService;
        this.deviceBindingPolicy = deviceBindingPolicy;
    }

    /**
     * Verifies registration for the loaded user, enforces device ownership, and persists a new key.
     * @param userId authenticated principal identifier
     * @param request signed registration response and device metadata
     * @return registered, user-not-found, or device-already-bound outcome
     */
    @Transactional
    public Result execute(Long userId, DeviceKeyRegistrationRequest request) {
        UserDataBase user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Result.userNotFound();
        }

        DeviceKeyService.VerifiedDeviceKeyRegistration verified =
                deviceKeyService.verifyRegistration(request, "", user.getUsername());
        var bindingConflict = deviceBindingPolicy.ensureDeviceAvailableForBind(
                verified.deviceInstallId(),
                user.getId(),
                request.isConfirmUnlinkDevice());
        if (bindingConflict != null) {
            return Result.deviceAlreadyBound(bindingConflict);
        }
        persistDeviceKey(user, verified);
        return Result.registered();
    }

    /**
     * Saves verified public credential material unless the same credential is already owned by the user.
     * @param user existing account receiving the credential
     * @param verified verified registration material and client metadata
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
     * Result of completing authenticated device-key registration.
     * @param status outcome of account lookup, ownership check, and persistence
     * @param deviceAlreadyBound conflict details, present only for {@link Status#DEVICE_ALREADY_BOUND}
     */
    public record Result(Status status, DeviceAlreadyBoundDTO deviceAlreadyBound) {

        /**
         * Builds a successful registration result.
         * @return registered result with no conflict payload
         */
        public static Result registered() {
            return new Result(Status.REGISTERED, null);
        }

        /**
         * Builds the missing-user result.
         * @return not-found result with no conflict payload
         */
        public static Result userNotFound() {
            return new Result(Status.USER_NOT_FOUND, null);
        }

        /**
         * Builds a result with device installation conflict details.
         * @param payload conflict information for client confirmation
         * @return device-already-bound result
         */
        public static Result deviceAlreadyBound(DeviceAlreadyBoundDTO payload) {
            return new Result(Status.DEVICE_ALREADY_BOUND, payload);
        }
    }

    /** Outcomes of completing authenticated device-key registration. */
    public enum Status {
        /** New device-key credential was persisted or already existed for this owner. */
        REGISTERED,
        /** Authenticated principal did not resolve to an account. */
        USER_NOT_FOUND,
        /** Device installation is owned elsewhere and requires explicit conflict handling. */
        DEVICE_ALREADY_BOUND
    }
}
