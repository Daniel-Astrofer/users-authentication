package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.application.usecase.backupcodes.BackupCodesOperationsUseCase;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.common.dto.ApiResponse;

/** Authenticated API for checking recovery-code availability and rotating one-time codes. */
@RestController
@RequestMapping("/auth/backup-codes")
public class BackupCodesController {

    private final BackupCodesOperationsUseCase backupCodesOperationsUseCase;

    /**
     * Creates the backup-code HTTP boundary.
     *
     * @param backupCodesOperationsUseCase use case that enforces authorization and code lifecycle rules
     */
    public BackupCodesController(BackupCodesOperationsUseCase backupCodesOperationsUseCase) {
        this.backupCodesOperationsUseCase = backupCodesOperationsUseCase;
    }

    /**
     * Returns the number and availability of remaining backup codes without exposing their hashes.
     *
     * @param authentication authenticated principal containing the account identifier
     * @return backup-code status envelope
     */
    @GetMapping
    public ResponseEntity<ApiResponse<BackupCodesStatusDTO>> getStatus(Authentication authentication) {
        BackupCodesStatusDTO response = backupCodesOperationsUseCase.getStatus(Long.parseLong(authentication.getName()));
        return ResponseEntity.ok(ApiResponse.success("Backup code status retrieved successfully.", response));
    }

    /**
     * Replaces all existing backup codes after step-up factor authorization and returns new raw codes once.
     *
     * @param authentication authenticated principal containing the account identifier
     * @param request optional TOTP, passkey, or confirmation passphrase material for step-up authorization
     * @return status envelope with the newly generated codes for one-time display
     */
    @PostMapping("/regenerate")
    public ResponseEntity<ApiResponse<BackupCodesStatusDTO>> regenerate(
            Authentication authentication,
            @RequestBody(required = false) RegenerateBackupCodesRequest request) {
        Long userId = Long.parseLong(authentication.getName());
        RegenerateBackupCodesRequest stepUpRequest = request != null ? request : RegenerateBackupCodesRequest.empty();
        BackupCodesStatusDTO response = backupCodesOperationsUseCase.regenerate(
                userId,
                stepUpRequest.totpCode(),
                stepUpRequest.passkeyAssertionJson(),
                stepUpRequest.confirmationPassphrase());
        return ResponseEntity.ok(ApiResponse.success("Backup codes regenerated successfully.", response));
    }

    /**
     * Optional step-up authentication factors accepted when rotating backup codes.
     * The use case validates the supplied evidence against the account's transactional authorization policy.
     *
     * @param totpCode optional current TOTP value
     * @param passkeyAssertionJson optional serialized WebAuthn assertion
     * @param confirmationPassphrase optional account confirmation passphrase
     */
    public record RegenerateBackupCodesRequest(
            String totpCode,
            String passkeyAssertionJson,
            String confirmationPassphrase) {

        /** Creates an empty factor request when the HTTP body is omitted. */
        private static RegenerateBackupCodesRequest empty() {
            return new RegenerateBackupCodesRequest(null, null, null);
        }
    }
}
