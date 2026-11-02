package com.kerosene.auth.application.usecase.me;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.account.AppPinService;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.auth.model.enums.UserRole;

import java.util.HashMap;
import java.util.Map;

/** Builds the current user's client profile using account data and device-scoped PIN status. */
@Component
public class GetCurrentUserProfileUseCase {

    /** User lookup boundary for the current profile. */
    private final UserServiceContract userServiceContract;
    /** Resolves whether the application PIN is configured for this specific device hash. */
    private final AppPinService appPinService;

    /**
     * Creates the profile query operation.
     * @param userServiceContract user lookup service
     * @param appPinService device-scoped PIN status service
     */
    public GetCurrentUserProfileUseCase(UserServiceContract userServiceContract, AppPinService appPinService) {
        this.userServiceContract = userServiceContract;
        this.appPinService = appPinService;
    }

    /**
     * Looks up the account and returns its public profile or a typed not-found result.
     * @param userId current principal's account identifier
     * @param deviceHash device reference used to resolve PIN state
     * @return profile result
     */
    public Result execute(Long userId, String deviceHash) {
        return userServiceContract.buscarPorId(userId)
                .map(user -> Result.found(profileFor(user, deviceHash)))
                .orElseGet(Result::notFound);
    }

    /**
     * Projects selected account and device-security fields into the response map.
     * @param user persisted account entity
     * @param deviceHash device reference for application PIN lookup
     * @return profile fields used by the client
     */
    private Map<String, Object> profileFor(UserDataBase user, String deviceHash) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", String.valueOf(user.getId()));
        response.put("userId", String.valueOf(user.getId()));
        response.put("username", user.getUsername());
        response.put("role", user.getRole().name());
        response.put("isAdmin", user.getRole() == UserRole.ADMIN);
        response.put("passkeyEnabledForTransactions", Boolean.TRUE.equals(user.getPasskeyEnabledForTransactions()));
        response.put("appPinEnabled", appPinService.getStatus(user, deviceHash).enabled());

        if (user.getCreatedAt() != null) {
            response.put("createdAt", user.getCreatedAt().toString());
        }

        return response;
    }

    /**
     * Result of fetching the current user's profile.
     * @param found whether an account was resolved
     * @param profile selected response fields, or {@code null} when absent
     */
    public record Result(boolean found, Map<String, Object> profile) {

        /**
         * Builds the result containing the profile projection.
         * @param profile projected response data
         * @return found result
         */
        private static Result found(Map<String, Object> profile) {
            return new Result(true, profile);
        }

        /**
         * Builds the missing-user result.
         * @return not-found result without profile data
         */
        private static Result notFound() {
            return new Result(false, null);
        }
    }
}
