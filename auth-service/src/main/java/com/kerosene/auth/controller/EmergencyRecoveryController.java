package com.kerosene.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.orchestrator.recovery.EmergencyRecoveryUseCase;
import com.kerosene.auth.dto.EmergencyRecoveryFinishRequest;
import com.kerosene.auth.dto.EmergencyRecoveryFinishResponse;
import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;
import com.kerosene.auth.dto.EmergencyRecoveryStartResponse;
import com.kerosene.common.dto.ApiResponse;

/** Translates emergency recovery start/finish requests and domain outcomes into HTTP responses. */
@RestController
@RequestMapping("/auth/recovery/emergency")
public class EmergencyRecoveryController {

    /** Recovery workflow boundary containing validation and credential rotation. */
    private final EmergencyRecoveryUseCase emergencyRecoveryUseCase;

    /** Creates the controller with the recovery orchestration boundary.
     * @param emergencyRecoveryUseCase performs recovery proof checks and state transitions
     */
    public EmergencyRecoveryController(EmergencyRecoveryUseCase emergencyRecoveryUseCase) {
        this.emergencyRecoveryUseCase = emergencyRecoveryUseCase;
    }

    /** Returns a fresh canonical challenge after validating recovery-session and new-authenticator ownership. */
    @PostMapping("/device-key/challenge")
    public ResponseEntity<ApiResponse<com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse>> deviceKeyChallenge(
            @RequestBody com.kerosene.auth.dto.EmergencyRecoveryDeviceKeyChallengeRequest request) {
        try {
            return ResponseEntity.ok(ApiResponse.success("Recovery device-key challenge prepared.",
                    emergencyRecoveryUseCase.prepareDeviceKeyChallenge(request)));
        } catch (AuthExceptions.RecoverySessionExpiredException exception) {
            return recoveryError(HttpStatus.GONE, "Recovery session is expired or consumed.", "RECOVERY_SESSION_EXPIRED");
        } catch (AuthExceptions.RecoveryRejectedException
                | com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException exception) {
            return recoveryError(HttpStatus.UNAUTHORIZED, "Recovery proof was rejected.", "RECOVERY_REJECTED");
        } catch (AuthExceptions.RecoveryRateLimitedException exception) {
            return recoveryError(HttpStatus.TOO_MANY_REQUESTS, "Recovery enrollment is rate limited.", "RECOVERY_RATE_LIMITED");
        } catch (IllegalArgumentException exception) {
            return recoveryError(HttpStatus.BAD_REQUEST, "Recovery challenge request is invalid.", "RECOVERY_BAD_REQUEST");
        }
    }

    /** Creates a short-lived recovery session after validating the submitted recovery factors.
     * @param request account, replacement passphrase, recovery codes, and proof-of-work data
     * @param httpRequest servlet request used to derive the abuse-control fingerprint
     * @return accepted session response or a sanitized validation/rate-limit error
     */
    @PostMapping("/start")
    public ResponseEntity<ApiResponse<EmergencyRecoveryStartResponse>> start(
            @RequestBody EmergencyRecoveryStartRequest request,
            HttpServletRequest httpRequest) {
        try {
            String clientFingerprint = EmergencyRecoveryUseCase.buildClientFingerprint(httpRequest);
            EmergencyRecoveryStartResponse response = emergencyRecoveryUseCase.start(request, clientFingerprint);
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(ApiResponse.success("Emergency recovery session created.", response));
        } catch (AuthExceptions.RecoveryRateLimitedException exception) {
            return recoveryError(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Emergency recovery is temporarily rate limited.",
                    "RECOVERY_RATE_LIMITED");
        } catch (AuthExceptions.RecoveryRejectedException
                | com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException exception) {
            return recoveryError(
                    HttpStatus.UNAUTHORIZED,
                    "Emergency recovery request was rejected.",
                    "RECOVERY_REJECTED");
        } catch (AuthExceptions.InvalidCredentials | AuthExceptions.InvalidPassphrase
                | AuthExceptions.UsernameCantBeNull | AuthExceptions.InvalidCharacterUsername
                | AuthExceptions.CharacterLimitException | AuthExceptions.PassphraseCantBeNull
                | IllegalArgumentException exception) {
            return recoveryError(
                    HttpStatus.BAD_REQUEST,
                    "Emergency recovery request is invalid.",
                    "RECOVERY_BAD_REQUEST");
        }
    }

    /** Consumes the recovery session and rotates credentials after final TOTP/passkey proof.
     * @param request session identifier and completion proofs
     * @return completed recovery response or a sanitized rejection/error
     */
    @PostMapping("/finish")
    public ResponseEntity<ApiResponse<EmergencyRecoveryFinishResponse>> finish(
            @RequestBody EmergencyRecoveryFinishRequest request) {
        try {
            EmergencyRecoveryFinishResponse response = emergencyRecoveryUseCase.finish(request);
            return ResponseEntity.ok(ApiResponse.success(
                    "Emergency recovery completed. Login again with the new credentials.", response));
        } catch (AuthExceptions.RecoverySessionExpiredException exception) {
            return recoveryError(
                    HttpStatus.GONE,
                    "Emergency recovery session is expired or already consumed.",
                    "RECOVERY_SESSION_EXPIRED");
        } catch (AuthExceptions.RecoveryRejectedException
                | com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException exception) {
            return recoveryError(
                    HttpStatus.UNAUTHORIZED,
                    "Emergency recovery request was rejected.",
                    "RECOVERY_REJECTED");
        } catch (IllegalArgumentException exception) {
            return recoveryError(
                    HttpStatus.BAD_REQUEST,
                    "Emergency recovery request is invalid.",
                    "RECOVERY_BAD_REQUEST");
        }
    }

    /** Builds the common error envelope returned for expected recovery failures.
     * @param status HTTP status to expose
     * @param message client-safe message
     * @param errorCode stable recovery error identifier
     * @param <T> response payload type expected by the calling endpoint
     * @return failed API response with no payload
     */
    private <T> ResponseEntity<ApiResponse<T>> recoveryError(HttpStatus status, String message, String errorCode) {
        return ResponseEntity.status(status)
                .body(new ApiResponse<>(false, message, null, errorCode));
    }
}
