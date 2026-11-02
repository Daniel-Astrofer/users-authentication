package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.usecase.security.GetAccountSecurityProfileUseCase;
import com.kerosene.auth.application.usecase.security.UpdateAccountSecurityProfileUseCase;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.dto.AccountSecurityProfileDTO;
import com.kerosene.auth.dto.AccountSecurityUpdateRequestDTO;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.common.dto.ApiResponse;

/** Authenticated HTTP API for reading and updating a user's account security profile. */
@RestController
@RequestMapping("/auth/security")
public class AccountSecurityController {

    private final UserServiceContract userService;
    private final GetAccountSecurityProfileUseCase getAccountSecurityProfileUseCase;
    private final UpdateAccountSecurityProfileUseCase updateAccountSecurityProfileUseCase;

    /**
     * Creates the controller with account lookup and profile use-case boundaries.
     *
     * @param userService resolves the authenticated account entity
     * @param getAccountSecurityProfileUseCase reads the current profile and device-scoped settings
     * @param updateAccountSecurityProfileUseCase validates and persists requested profile changes
     */
    public AccountSecurityController(
            UserServiceContract userService,
            GetAccountSecurityProfileUseCase getAccountSecurityProfileUseCase,
            UpdateAccountSecurityProfileUseCase updateAccountSecurityProfileUseCase) {
        this.userService = userService;
        this.getAccountSecurityProfileUseCase = getAccountSecurityProfileUseCase;
        this.updateAccountSecurityProfileUseCase = updateAccountSecurityProfileUseCase;
    }

    /**
     * Reads the authenticated user's security profile, optionally scoped to a known device hash.
     *
     * @param deviceHash optional device binding context for device-specific settings
     * @return profile response envelope
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<AccountSecurityProfileDTO>> getProfile(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash) {
        UserDataBase user = getAuthenticatedUser();
        return ResponseEntity.ok(ApiResponse.success(
                "Account security profile retrieved successfully.",
                getAccountSecurityProfileUseCase.execute(user, deviceHash)));
    }

    /**
     * Validates and updates the authenticated user's profile, passing device context to the use case.
     *
     * @param deviceHash optional device binding context used by device-scoped rules
     * @param request requested account-security changes
     * @return updated profile response envelope
     */
    @PutMapping("/profile")
    public ResponseEntity<ApiResponse<AccountSecurityProfileDTO>> updateProfile(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash,
            @RequestBody AccountSecurityUpdateRequestDTO request) {
        UserDataBase user = getAuthenticatedUser();
        return ResponseEntity.ok(ApiResponse.success(
                "Account security profile updated successfully.",
                updateAccountSecurityProfileUseCase.execute(user, request, deviceHash)));
    }

    /** Resolves the current security principal to an account row or rejects invalid authentication context. */
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
