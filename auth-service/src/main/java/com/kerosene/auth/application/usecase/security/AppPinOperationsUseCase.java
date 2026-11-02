package com.kerosene.auth.application.usecase.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.account.AppPinService;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.dto.AppPinStatusDTO;
import com.kerosene.auth.dto.ConfigureAppPinRequestDTO;
import com.kerosene.auth.dto.VerifyAppPinRequestDTO;
import com.kerosene.auth.model.entity.UserDataBase;

/** Executes authenticated app-PIN status, setup, and verification operations for the current account. */
@Component
public class AppPinOperationsUseCase {

    /** Resolves the authenticated principal to its persisted user entity. */
    private final UserServiceContract userService;
    /** Implements per-device app-PIN status and mutation rules. */
    private final AppPinService appPinService;

    /**
     * Creates app-PIN operations for the currently authenticated account.
     *
     * @param userService resolves the security principal to a persisted account
     * @param appPinService applies device-scoped PIN policy and persistence
     */
    public AppPinOperationsUseCase(UserServiceContract userService, AppPinService appPinService) {
        this.userService = userService;
        this.appPinService = appPinService;
    }

    /**
     * Returns PIN status for the authenticated account and optional device reference.
     *
     * @param deviceHash registered device hash, or null when the client has not identified its device
     * @return app-PIN status and current policy limits
     */
    public AppPinStatusDTO getStatus(String deviceHash) {
        return appPinService.getStatus(getAuthenticatedUser(), deviceHash);
    }

    /**
     * Enables, replaces, or disables PIN protection for the authenticated account and device.
     *
     * @param deviceHash registered device hash required for a mutation
     * @param request requested enabled state and required authorization material
     * @return updated PIN status
     */
    public AppPinStatusDTO configure(String deviceHash, ConfigureAppPinRequestDTO request) {
        return appPinService.configure(getAuthenticatedUser(), deviceHash, request);
    }

    /**
     * Verifies the submitted local PIN for the authenticated account and device.
     *
     * @param deviceHash registered device hash identifying the PIN record
     * @param request verification input containing the candidate PIN
     * @return updated status after successful verification
     */
    public AppPinStatusDTO verify(String deviceHash, VerifyAppPinRequestDTO request) {
        return appPinService.verify(getAuthenticatedUser(), deviceHash, request.getPin());
    }

    /**
     * Resolves the current security principal to the persisted account required by PIN operations.
     *
     * @return authenticated account entity
     * @throws AuthExceptions.InvalidCredentials when principal is absent, malformed, or no longer exists
     */
    private UserDataBase getAuthenticatedUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AuthExceptions.InvalidCredentials("Not authenticated.");
        }

        try {
            Long userId = Long.parseLong(auth.getName());
            return userService.buscarPorId(userId)
                    .orElseThrow(() -> new AuthExceptions.InvalidCredentials("Authenticated user not found."));
        } catch (NumberFormatException e) {
            throw new AuthExceptions.InvalidCredentials("Invalid authentication context.");
        }
    }
}
