package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.kerosene.auth.application.usecase.security.AppPinOperationsUseCase;
import com.kerosene.auth.application.usecase.security.RecoverAppPinUseCase;
import com.kerosene.auth.dto.AppPinStatusDTO;
import com.kerosene.auth.dto.ConfigureAppPinRequestDTO;
import com.kerosene.auth.dto.VerifyAppPinRequestDTO;
import com.kerosene.auth.dto.RecoverAppPinRequestDTO;
import com.kerosene.common.dto.ApiResponse;

/** Authenticated REST endpoints for reading, configuring, and verifying a device-scoped app PIN. */
@RestController
@RequestMapping("/auth/security/app-pin")
public class AppPinController {

    private final AppPinOperationsUseCase appPinOperationsUseCase;
    private final RecoverAppPinUseCase recoverAppPinUseCase;

    /**
     * Creates the PIN controller.
     *
     * @param appPinOperationsUseCase authenticated PIN operations facade
     * @param recoverAppPinUseCase password-and-passkey PIN recovery boundary
     */
    public AppPinController(AppPinOperationsUseCase appPinOperationsUseCase,
            RecoverAppPinUseCase recoverAppPinUseCase) {
        this.appPinOperationsUseCase = appPinOperationsUseCase;
        this.recoverAppPinUseCase = recoverAppPinUseCase;
    }

    /**
     * Returns PIN state for the authenticated user and optional device hash.
     *
     * @param deviceHash optional {@code X-Device-Hash} identifying the local PIN settings
     * @return status envelope; without a device hash, returns default disabled status
     */
    @GetMapping
    public ResponseEntity<ApiResponse<AppPinStatusDTO>> getStatus(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash) {
        AppPinStatusDTO status = appPinOperationsUseCase.getStatus(deviceHash);
        return ResponseEntity.ok(ApiResponse.success("App PIN status retrieved successfully.", status));
    }

    /**
     * Creates or updates the authenticated user's PIN settings for the identified device.
     * Reconfiguration of an enabled PIN requires the current PIN or an active TOTP code.
     *
     * @param deviceHash device hash required to scope the mutation
     * @param request requested enabled state, PIN, and any reconfiguration proof
     * @return resulting PIN status envelope
     */
    @PutMapping
    public ResponseEntity<ApiResponse<AppPinStatusDTO>> configure(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash,
            @RequestBody ConfigureAppPinRequestDTO request) {
        AppPinStatusDTO status = appPinOperationsUseCase.configure(deviceHash, request);
        return ResponseEntity.ok(ApiResponse.success("App PIN settings updated successfully.", status));
    }

    /**
     * Verifies a local PIN and updates attempt counters or lockout state.
     *
     * @param deviceHash device hash selecting the PIN settings
     * @param request candidate PIN
     * @return updated status on success; service errors include status for failed attempts
     */
    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<AppPinStatusDTO>> verify(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash,
            @RequestBody VerifyAppPinRequestDTO request) {
        AppPinStatusDTO status = appPinOperationsUseCase.verify(deviceHash, request);
        return ResponseEntity.ok(ApiResponse.success("App PIN verified successfully.", status));
    }

    /**
     * Replaces the current device PIN after fresh account password and passkey verification.
     *
     * @param deviceHash required device hash selecting the PIN to recover
     * @param request account password, fresh device-key assertion, and four-digit new PIN
     * @return resulting enabled PIN status
     */
    @PostMapping("/recover")
    public ResponseEntity<ApiResponse<AppPinStatusDTO>> recover(
            @RequestHeader(value = "X-Device-Hash", required = false) String deviceHash,
            @RequestBody RecoverAppPinRequestDTO request) {
        AppPinStatusDTO status = recoverAppPinUseCase.execute(deviceHash, request);
        return ResponseEntity.ok(ApiResponse.success("App PIN recovered successfully.", status));
    }
}
