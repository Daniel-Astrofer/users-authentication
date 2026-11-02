package com.kerosene.auth.application.usecase.devicekey;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse;
import com.kerosene.auth.model.entity.UserDataBase;

/** Creates an authentication challenge for a device-key credential owned by a username. */
@Component
public class GetDeviceKeyAuthenticationChallengeUseCase {

    /** User lookup used to bind challenge issuance to an existing account. */
    private final UserRepository userRepository;
    /** Device-key service that generates a challenge for the account's registered keys. */
    private final DeviceKeyService deviceKeyService;

    /**
     * Creates the authentication challenge use case.
     * @param userRepository user lookup repository
     * @param deviceKeyService device-key challenge generator
     */
    public GetDeviceKeyAuthenticationChallengeUseCase(
            UserRepository userRepository,
            DeviceKeyService deviceKeyService) {
        this.userRepository = userRepository;
        this.deviceKeyService = deviceKeyService;
    }

    /**
     * Normalizes the username, returns a not-found result or delegates challenge generation.
     * @param username account username submitted for device-key authentication
     * @return generated challenge or not-found result
     */
    @Transactional(readOnly = true)
    public Result execute(String username) {
        UserDataBase user = userRepository.findByUsername(DeviceKeyUsernameSupport.normalizeUsername(username));
        if (user == null) {
            return Result.userNotFound();
        }

        return Result.generated(deviceKeyService.startAuthenticationChallenge(user));
    }

    /**
     * Result of requesting a device-key authentication challenge.
     * @param status whether generation succeeded or the account was absent
     * @param message optional public message, populated for user-not-found
     * @param challenge challenge payload, populated on successful generation
     */
    public record Result(Status status, String message, DeviceKeyChallengeResponse challenge) {

        /**
         * Builds the account-not-found response.
         * @return result with a public not-found message
         */
        public static Result userNotFound() {
            return new Result(Status.USER_NOT_FOUND, "User not found", null);
        }

        /**
         * Builds the successful challenge response.
         * @param challenge generated device-key challenge
         * @return result containing the challenge
         */
        public static Result generated(DeviceKeyChallengeResponse challenge) {
            return new Result(Status.GENERATED, null, challenge);
        }
    }

    /** Outcomes of requesting a device-key authentication challenge. */
    public enum Status {
        /** A challenge was generated for the account. */
        GENERATED,
        /** No account matched the normalized username. */
        USER_NOT_FOUND
    }
}
