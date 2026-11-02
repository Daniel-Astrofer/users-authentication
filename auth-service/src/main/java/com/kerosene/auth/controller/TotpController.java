package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.application.usecase.totp.TotpOperationsUseCase;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.auth.dto.TotpSetupResponseDTO;
import com.kerosene.common.dto.ApiResponse;

import java.util.Map;

@RestController
@RequestMapping("/auth/totp")
public class TotpController {

    private final TotpOperationsUseCase totpOperationsUseCase;

    public TotpController(TotpOperationsUseCase totpOperationsUseCase) {
        this.totpOperationsUseCase = totpOperationsUseCase;
    }

    @PostMapping("/setup")
    public ResponseEntity<ApiResponse<TotpSetupResponseDTO>> setup(Authentication authentication) {
        TotpSetupResponseDTO response = totpOperationsUseCase.setup(Long.parseLong(authentication.getName()));
        return ResponseEntity.ok(ApiResponse.success("TOTP setup secret generated successfully.", response));
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<BackupCodesStatusDTO>> verify(
            Authentication authentication,
            @RequestBody Map<String, String> request) {
        BackupCodesStatusDTO response = totpOperationsUseCase.verify(
                Long.parseLong(authentication.getName()),
                request.get("totpCode"));
        return ResponseEntity.ok(ApiResponse.success("TOTP enabled successfully.", response));
    }

    /** Compatibility entry point; omitted factors are still checked by the use case. */
    public ResponseEntity<ApiResponse<String>> disable(Authentication authentication) {
        return disable(authentication, null);
    }

    /** Disables the authenticator with optional account-security factors. */
    @DeleteMapping
    public ResponseEntity<ApiResponse<String>> disable(Authentication authentication,
            @RequestBody(required = false) DisableTotpRequest request) {
        DisableTotpRequest factors = request != null ? request : new DisableTotpRequest(null, null, null);
        totpOperationsUseCase.disable(Long.parseLong(authentication.getName()),
                factors.totpCode(), factors.passkeyAssertionJson(), factors.confirmationPassphrase());
        return ResponseEntity.ok(ApiResponse.success("TOTP disabled successfully.", "OK"));
    }
    /** One-use factors authorized against the authenticated account.
     * @param totpCode authenticator code
     * @param passkeyAssertionJson signed device/passkey proof
     * @param confirmationPassphrase account confirmation phrase
     */
    public record DisableTotpRequest(String totpCode, String passkeyAssertionJson,
            String confirmationPassphrase) {}
}
