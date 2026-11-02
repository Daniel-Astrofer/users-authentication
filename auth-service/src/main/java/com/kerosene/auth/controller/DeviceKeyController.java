package com.kerosene.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.service.devicekey.DeviceKeyChallengeException;
import com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException;
import com.kerosene.auth.application.service.devicekey.DeviceKeyReplayException;
import com.kerosene.auth.application.usecase.devicekey.FinishAuthenticatedDeviceKeyRegistrationUseCase;
import com.kerosene.auth.application.usecase.devicekey.FinishOnboardingDeviceKeyRegistrationUseCase;
import com.kerosene.auth.application.usecase.devicekey.GetDeviceKeyAuthenticationChallengeUseCase;
import com.kerosene.auth.application.usecase.devicekey.ManageDeviceKeyDevicesUseCase;
import com.kerosene.auth.application.usecase.devicekey.StartAuthenticatedDeviceKeyRegistrationUseCase;
import com.kerosene.auth.application.usecase.devicekey.StartOnboardingDeviceKeyRegistrationUseCase;
import com.kerosene.auth.application.usecase.devicekey.VerifyDeviceKeyLoginUseCase;
import com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse;
import com.kerosene.auth.dto.devicekey.DeviceKeyDeviceDTO;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.common.exception.ErrorCodes;
import com.kerosene.common.exception.FinancialProviderUnavailableException;

import java.util.List;

/**
 * HTTP boundary for onboarding and authenticated device-key registration, challenge login,
 * and account-scoped device revocation. Protocol failures are mapped to stable client error codes
 * while account creation and infrastructure readiness failures remain available to global handlers.
 */
@RestController
@RequestMapping("/auth/device-key")
public class DeviceKeyController {

    private static final Logger log = LoggerFactory.getLogger(DeviceKeyController.class);
    private static final String DEVICE_KEY_GENERIC_ERROR = "Device key request failed.";
    private static final String DEVICE_KEY_CHALLENGE_ERROR = "Device key challenge is required or expired.";
    private static final String DEVICE_KEY_ASSERTION_ERROR = "Device key assertion could not be verified.";
    private static final String DEVICE_KEY_REPLAY_ERROR = "Device key request was rejected by replay protection.";

    private final GetDeviceKeyAuthenticationChallengeUseCase getDeviceKeyAuthenticationChallengeUseCase;
    private final ManageDeviceKeyDevicesUseCase manageDeviceKeyDevicesUseCase;
    private final StartOnboardingDeviceKeyRegistrationUseCase startOnboardingDeviceKeyRegistrationUseCase;
    private final StartAuthenticatedDeviceKeyRegistrationUseCase startAuthenticatedDeviceKeyRegistrationUseCase;
    private final FinishAuthenticatedDeviceKeyRegistrationUseCase finishAuthenticatedDeviceKeyRegistrationUseCase;
    private final FinishOnboardingDeviceKeyRegistrationUseCase finishOnboardingDeviceKeyRegistrationUseCase;
    private final VerifyDeviceKeyLoginUseCase verifyDeviceKeyLoginUseCase;

    /**
     * Creates the device-key controller with separate use cases for each lifecycle transition.
     *
     * @param getDeviceKeyAuthenticationChallengeUseCase creates public login challenges
     * @param manageDeviceKeyDevicesUseCase lists and revokes account-owned credentials
     * @param startOnboardingDeviceKeyRegistrationUseCase creates challenges tied to signup sessions
     * @param startAuthenticatedDeviceKeyRegistrationUseCase creates challenges for signed-in accounts
     * @param finishAuthenticatedDeviceKeyRegistrationUseCase verifies and persists authenticated registration
     * @param finishOnboardingDeviceKeyRegistrationUseCase verifies registration before creating an account
     * @param verifyDeviceKeyLoginUseCase verifies a challenge signature and establishes login state
     */
    public DeviceKeyController(
            GetDeviceKeyAuthenticationChallengeUseCase getDeviceKeyAuthenticationChallengeUseCase,
            ManageDeviceKeyDevicesUseCase manageDeviceKeyDevicesUseCase,
            StartOnboardingDeviceKeyRegistrationUseCase startOnboardingDeviceKeyRegistrationUseCase,
            StartAuthenticatedDeviceKeyRegistrationUseCase startAuthenticatedDeviceKeyRegistrationUseCase,
            FinishAuthenticatedDeviceKeyRegistrationUseCase finishAuthenticatedDeviceKeyRegistrationUseCase,
            FinishOnboardingDeviceKeyRegistrationUseCase finishOnboardingDeviceKeyRegistrationUseCase,
            VerifyDeviceKeyLoginUseCase verifyDeviceKeyLoginUseCase) {
        this.getDeviceKeyAuthenticationChallengeUseCase = getDeviceKeyAuthenticationChallengeUseCase;
        this.manageDeviceKeyDevicesUseCase = manageDeviceKeyDevicesUseCase;
        this.startOnboardingDeviceKeyRegistrationUseCase = startOnboardingDeviceKeyRegistrationUseCase;
        this.startAuthenticatedDeviceKeyRegistrationUseCase = startAuthenticatedDeviceKeyRegistrationUseCase;
        this.finishAuthenticatedDeviceKeyRegistrationUseCase = finishAuthenticatedDeviceKeyRegistrationUseCase;
        this.finishOnboardingDeviceKeyRegistrationUseCase = finishOnboardingDeviceKeyRegistrationUseCase;
        this.verifyDeviceKeyLoginUseCase = verifyDeviceKeyLoginUseCase;
    }

    /**
     * Starts device-key enrollment inside a pending signup session.
     *
     * @param sessionId signup session identifier owning the challenge
     * @param username optional account name associated with the signup session
     * @return challenge response, or 404 when the signup session expired
     */
    @PostMapping("/onboarding/start")
    public ResponseEntity<ApiResponse<DeviceKeyChallengeResponse>> startOnboardingRegistration(
            @RequestParam String sessionId,
            @RequestParam(required = false) String username) {
        StartOnboardingDeviceKeyRegistrationUseCase.Result result =
                startOnboardingDeviceKeyRegistrationUseCase.execute(sessionId, username);
        if (result.status() == StartOnboardingDeviceKeyRegistrationUseCase.Status.SESSION_EXPIRED) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Session expired", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        return ResponseEntity.ok(ApiResponse.success("Device key challenge generated", result.challenge()));
    }

    /**
     * Verifies a signup-bound device-key response, completes account creation, and returns its token.
     *
     * @param sessionId signup session used to start the challenge
     * @param request challenge assertion and device public-key registration data
     * @return session token, conflict for an already-bound device, or a mapped protocol error
     */
    @PostMapping("/onboarding/finish")
    public ResponseEntity<ApiResponse<?>> finishOnboardingRegistration(
            @RequestParam String sessionId,
            @RequestBody DeviceKeyRegistrationRequest request) {
        try {
            FinishOnboardingDeviceKeyRegistrationUseCase.Result result =
                    finishOnboardingDeviceKeyRegistrationUseCase.execute(sessionId, request);
            if (result.status() == FinishOnboardingDeviceKeyRegistrationUseCase.Status.SESSION_EXPIRED) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.error("Session expired", ErrorCodes.AUTH_SESSION_EXPIRED));
            }
            if (result.status() == FinishOnboardingDeviceKeyRegistrationUseCase.Status.DEVICE_ALREADY_BOUND) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponse.error(
                                result.deviceAlreadyBound() == null
                                        ? "Device already bound to another account"
                                        : result.deviceAlreadyBound().message(),
                                ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                                result.deviceAlreadyBound()));
            }
            return ResponseEntity.ok(ApiResponse.success(
                    "Device key linked and account created.",
                    result.token()));
        } catch (DeviceKeyChallengeException exception) {
            return ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED)
                    .body(ApiResponse.error(DEVICE_KEY_CHALLENGE_ERROR, ErrorCodes.AUTH_PASSKEY_CHALLENGE));
        } catch (DeviceKeyProtocolException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(DEVICE_KEY_ASSERTION_ERROR, ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED));
        } catch (FinancialProviderUnavailableException
                 | FinalizeSignupAccount.VaultNotReadyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            log.error("Device key onboarding failed", exception);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error(DEVICE_KEY_GENERIC_ERROR, ErrorCodes.AUTH_GENERIC));
        }
    }

    /**
     * Issues an authentication challenge for a username that has a registered device key.
     *
     * @param username account name whose device-key credential should be challenged
     * @return challenge response, or 404 when the account cannot be found
     */
    @GetMapping("/challenge")
    public ResponseEntity<ApiResponse<DeviceKeyChallengeResponse>> getChallenge(@RequestParam String username) {
        GetDeviceKeyAuthenticationChallengeUseCase.Result result =
                getDeviceKeyAuthenticationChallengeUseCase.execute(username);
        if (result.status() == GetDeviceKeyAuthenticationChallengeUseCase.Status.USER_NOT_FOUND) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(result.message(), ErrorCodes.AUTH_USER_NOT_FOUND));
        }
        return ResponseEntity.ok(ApiResponse.success(
                "Device key challenge generated",
                result.challenge()));
    }

    /**
     * Starts device-key enrollment for the currently authenticated account.
     *
     * @return challenge response or 401 when no authenticated user is available
     */
    @PostMapping("/register/start")
    public ResponseEntity<ApiResponse<DeviceKeyChallengeResponse>> startAuthenticatedRegistration() {
        Long userId = authenticatedUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to register a device key", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        StartAuthenticatedDeviceKeyRegistrationUseCase.Result result =
                startAuthenticatedDeviceKeyRegistrationUseCase.execute(userId);
        if (result.status() == StartAuthenticatedDeviceKeyRegistrationUseCase.Status.USER_NOT_FOUND) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to register a device key", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        return ResponseEntity.ok(ApiResponse.success(
                "Device key registration challenge generated",
                result.challenge()));
    }

    /**
     * Verifies the authenticated registration assertion and stores the new device-key credential.
     *
     * @param request challenge assertion, public key, and device metadata
     * @return success envelope, conflict for another account's binding, or mapped protocol error
     */
    @PostMapping("/register/finish")
    public ResponseEntity<ApiResponse<?>> finishAuthenticatedRegistration(
            @RequestBody DeviceKeyRegistrationRequest request) {
        Long userId = authenticatedUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to register a device key", ErrorCodes.AUTH_SESSION_EXPIRED));
        }
        try {
            FinishAuthenticatedDeviceKeyRegistrationUseCase.Result result =
                    finishAuthenticatedDeviceKeyRegistrationUseCase.execute(userId, request);
            if (result.status() == FinishAuthenticatedDeviceKeyRegistrationUseCase.Status.USER_NOT_FOUND) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.error("Must be logged in to register a device key", ErrorCodes.AUTH_SESSION_EXPIRED));
            }
            if (result.status() == FinishAuthenticatedDeviceKeyRegistrationUseCase.Status.DEVICE_ALREADY_BOUND) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponse.error(
                                result.deviceAlreadyBound() == null
                                        ? "Device already bound to another account"
                                        : result.deviceAlreadyBound().message(),
                                ErrorCodes.AUTH_DEVICE_ALREADY_BOUND,
                                result.deviceAlreadyBound()));
            }
            return ResponseEntity.ok(ApiResponse.success("Device key registered successfully", "OK"));
        } catch (DeviceKeyChallengeException exception) {
            return ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED)
                    .body(ApiResponse.error(DEVICE_KEY_CHALLENGE_ERROR, ErrorCodes.AUTH_PASSKEY_CHALLENGE));
        } catch (DeviceKeyProtocolException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(DEVICE_KEY_ASSERTION_ERROR, ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED));
        }
    }

    /**
     * Verifies a device-key login assertion and maps its protocol result to an HTTP response.
     * A successful signature may still return 202 when the account requires a TOTP continuation.
     *
     * @param request credential identifier, signed challenge, and proof fields
     * @return authentication result, optional TOTP continuation data, or a mapped protocol failure
     */
    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<Object>> verifyAndLogin(@RequestBody DeviceKeyVerifyRequest request) {
        try {
            VerifyDeviceKeyLoginUseCase.Result result = verifyDeviceKeyLoginUseCase.execute(request);
            return mapVerifyResult(result);
        } catch (DeviceKeyReplayException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(DEVICE_KEY_REPLAY_ERROR, ErrorCodes.AUTH_PASSKEY_REPLAY));
        } catch (DeviceKeyChallengeException exception) {
            return ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED)
                    .body(ApiResponse.error(DEVICE_KEY_CHALLENGE_ERROR, ErrorCodes.AUTH_PASSKEY_CHALLENGE));
        } catch (DeviceKeyProtocolException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(DEVICE_KEY_ASSERTION_ERROR, ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED));
        } catch (FinancialProviderUnavailableException
                 | FinalizeSignupAccount.VaultNotReadyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            log.error("Device key verification failed", exception);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error(DEVICE_KEY_GENERIC_ERROR, ErrorCodes.AUTH_GENERIC));
        }
    }

    /** Maps each device-key verification state to its stable HTTP status and error code. */
    private ResponseEntity<ApiResponse<Object>> mapVerifyResult(VerifyDeviceKeyLoginUseCase.Result result) {
        return switch (result.status()) {
            case INVALID_CREDENTIAL_ID -> ResponseEntity.badRequest()
                    .body(ApiResponse.error("credentialId is required", ErrorCodes.SYS_INVALID_ARGUMENTS));
            case CREDENTIAL_NOT_FOUND -> credentialNotFound();
            case USER_NOT_FOUND -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("User not found", ErrorCodes.AUTH_USER_NOT_FOUND));
            case REPLAY_COUNTER_NOT_ADVANCED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(
                            "Device key counter did not advance.",
                            ErrorCodes.AUTH_PASSKEY_REPLAY));
            case INACTIVE_ACCOUNT -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Account is inactive", ErrorCodes.AUTH_INVALID_CREDENTIALS));
            case TOTP_REQUIRED -> ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(ApiResponse.success("Device key verified. TOTP required.", result.data()));
            case AUTHENTICATED -> ResponseEntity.ok(ApiResponse.success("Device key authentication successful", result.data()));
        };
    }

    /**
     * Lists device-key credentials owned by the authenticated account.
     *
     * @return device summaries or 401 when the request has no authenticated account
     */
    @GetMapping("/devices")
    public ResponseEntity<ApiResponse<List<DeviceKeyDeviceDTO>>> getRegisteredDevices() {
        Long userId = authenticatedUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to inspect device keys", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        ManageDeviceKeyDevicesUseCase.Result result = manageDeviceKeyDevicesUseCase.listDevices(userId);
        if (result.status() == ManageDeviceKeyDevicesUseCase.Status.USER_NOT_FOUND) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to inspect device keys", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        return ResponseEntity.ok(ApiResponse.success("Registered device keys retrieved.", result.devices()));
    }

    /**
     * Revokes one credential scoped to the authenticated account and returns the refreshed device list.
     *
     * @param credentialId credential identifier to revoke
     * @return refreshed credential list, 404 for an unknown credential, or 401 when unauthenticated
     */
    @PostMapping("/devices/{credentialId}/revoke")
    public ResponseEntity<ApiResponse<List<DeviceKeyDeviceDTO>>> revokeDevice(@PathVariable String credentialId) {
        Long userId = authenticatedUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to revoke device keys", ErrorCodes.AUTH_SESSION_EXPIRED));
        }

        ManageDeviceKeyDevicesUseCase.Result result = manageDeviceKeyDevicesUseCase.revokeDevice(userId, credentialId);
        if (result.status() == ManageDeviceKeyDevicesUseCase.Status.USER_NOT_FOUND) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Must be logged in to revoke device keys", ErrorCodes.AUTH_SESSION_EXPIRED));
        }
        if (result.status() == ManageDeviceKeyDevicesUseCase.Status.CREDENTIAL_NOT_FOUND) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Device key not found", ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND));
        }

        return ResponseEntity.ok(ApiResponse.success("Device key revoked.", result.devices()));
    }

    /** Builds the stable unauthorized response used when a credential cannot authenticate this account. */
    private ResponseEntity<ApiResponse<Object>> credentialNotFound() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(
                        "Esta chave deste dispositivo nao esta vinculada a conta.",
                        ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND));
    }

    /**
     * Reads the current Spring Security principal as a numeric persisted user identifier.
     *
     * @return authenticated user ID, or null for absent, anonymous, or unauthenticated principals
     */
    private Long authenticatedUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getName().equals("anonymousUser")) {
            return null;
        }
        return Long.parseLong(auth.getName());
    }

}
