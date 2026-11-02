package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.application.usecase.security.GetAccountSecurityStatusUseCase;
import com.kerosene.auth.dto.AccountSecurityStatusDTO;
import com.kerosene.common.dto.ApiResponse;

/** Authenticated read-only endpoint for the account's consolidated security readiness summary. */
@RestController
@RequestMapping("/auth/security-status")
public class AccountSecurityStatusController {

    private final GetAccountSecurityStatusUseCase getAccountSecurityStatusUseCase;

    /**
     * Creates the status endpoint with its query use case.
     *
     * @param getAccountSecurityStatusUseCase application query for account security state
     */
    public AccountSecurityStatusController(GetAccountSecurityStatusUseCase getAccountSecurityStatusUseCase) {
        this.getAccountSecurityStatusUseCase = getAccountSecurityStatusUseCase;
    }

    /**
     * Returns security and recovery readiness for the authenticated principal.
     *
     * @param authentication authenticated Spring Security principal whose name contains the user ID
     * @return consolidated password, passkey, TOTP, recovery-code, and activation state
     */
    @GetMapping
    public ResponseEntity<ApiResponse<AccountSecurityStatusDTO>> getStatus(Authentication authentication) {
        AccountSecurityStatusDTO status =
                getAccountSecurityStatusUseCase.execute(Long.parseLong(authentication.getName()));
        return ResponseEntity.ok(ApiResponse.success("Account security status retrieved successfully.", status));
    }
}
