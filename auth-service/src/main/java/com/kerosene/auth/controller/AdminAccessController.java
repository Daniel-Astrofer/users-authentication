package com.kerosene.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.admin.AdminAccessService;
import com.kerosene.auth.dto.AdminAccessAttemptDTO;
import com.kerosene.auth.dto.AdminAccessDecisionRequestDTO;
import com.kerosene.auth.dto.AdminAuthenticatedDeviceDTO;
import com.kerosene.auth.dto.AdminKeyCreateRequestDTO;
import com.kerosene.auth.dto.AdminKeyStatusDTO;
import com.kerosene.auth.dto.AdminLoginRequestDTO;
import com.kerosene.auth.dto.AdminLoginResponseDTO;
import com.kerosene.auth.model.enums.AdminAccessDeviceStatus;
import com.kerosene.common.dto.ApiResponse;

/**
 * HTTP boundary for admin login approval, administrator keys, and trusted admin devices.
 * Login and polling routes are available before an admin session exists; management routes
 * require the authenticated administrator role declared by their security annotations.
 */
@RestController
@RequestMapping("/auth/admin")
public class AdminAccessController {

    private final AdminAccessService adminAccessService;

    /**
     * Creates the controller with its admin access use-case boundary.
     *
     * @param adminAccessService application service enforcing admin access lifecycle rules
     */
    public AdminAccessController(AdminAccessService adminAccessService) {
        this.adminAccessService = adminAccessService;
    }

    /**
     * Starts a browser login attempt and returns 202 while mobile approval is pending.
     * The service receives the request address and user-agent as risk signals.
     *
     * @param request submitted administrator login credentials
     * @param httpRequest servlet request used to capture client network metadata
     * @return accepted login challenge or a structured authentication failure
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AdminLoginResponseDTO>> startLogin(
            @RequestBody AdminLoginRequestDTO request,
            HttpServletRequest httpRequest) {
        try {
            AdminLoginResponseDTO response = adminAccessService.startLogin(
                    request,
                    clientAddress(httpRequest),
                    httpRequest.getHeader("User-Agent"));
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(ApiResponse.success("Admin login pending mobile approval.", response));
        } catch (AuthExceptions.StructuredAuthException exception) {
            return ResponseEntity.status(exception.getStatus())
                    .body(ApiResponse.error(exception.getMessage(), exception.getErrorCode(), null));
        }
    }

    /**
     * Polls an existing login attempt and reports pending or completed authentication.
     *
     * @param attemptId identifier returned by {@link #startLogin(AdminLoginRequestDTO, HttpServletRequest)}
     * @param httpRequest current request used to bind polling to client context
     * @return 202 while mobile approval is required, 200 when the attempt is complete, or an auth error
     */
    @GetMapping("/login/{attemptId}")
    public ResponseEntity<ApiResponse<AdminLoginResponseDTO>> pollLogin(
            @PathVariable UUID attemptId,
            HttpServletRequest httpRequest) {
        try {
            AdminLoginResponseDTO response = adminAccessService.pollLogin(
                    attemptId,
                    clientAddress(httpRequest),
                    httpRequest.getHeader("User-Agent"));
            HttpStatus status = response.requiresMobileApproval() ? HttpStatus.ACCEPTED : HttpStatus.OK;
            return ResponseEntity.status(status).body(ApiResponse.success(response.message(), response));
        } catch (AuthExceptions.StructuredAuthException exception) {
            return ResponseEntity.status(exception.getStatus())
                    .body(ApiResponse.error(exception.getMessage(), exception.getErrorCode(), null));
        }
    }

    /**
     * Creates or rotates the current administrator's access key without returning key material.
     * Requires the ADMIN role.
     *
     * @param request validated key creation or rotation parameters
     * @return persisted key status and metadata
     */
    @PostMapping("/key")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminKeyStatusDTO>> createOrRotateKey(
            @RequestBody AdminKeyCreateRequestDTO request) {
        AdminKeyStatusDTO response = adminAccessService.createOrRotateKey(authenticatedUserId(), request);
        return ResponseEntity.ok(ApiResponse.success("Admin key configured.", response));
    }

    /**
     * Returns key configuration metadata without exposing key material. Requires the ADMIN role.
     *
     * @return status and non-secret metadata for the authenticated administrator's key
     */
    @GetMapping("/key")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminKeyStatusDTO>> keyStatus() {
        return ResponseEntity.ok(ApiResponse.success(
                "Admin key status retrieved.",
                adminAccessService.keyStatus(authenticatedUserId())));
    }

    /**
     * Revokes the current administrator's access key. Requires the ADMIN role.
     *
     * @return post-revocation key status
     */
    @DeleteMapping("/key")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminKeyStatusDTO>> revokeKey() {
        return ResponseEntity.ok(ApiResponse.success(
                "Admin key revoked.",
                adminAccessService.revokeKey(authenticatedUserId())));
    }

    /**
     * Lists pending access attempts visible to the authenticated administrator.
     *
     * @return pending attempts eligible for that administrator's review
     */
    @GetMapping("/access-attempts/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<AdminAccessAttemptDTO>>> pendingAttempts() {
        return ResponseEntity.ok(ApiResponse.success(
                "Pending admin access attempts retrieved.",
                adminAccessService.pendingAttempts(authenticatedUserId())));
    }

    /**
     * Approves or denies a pending attempt for the authenticated administrator.
     *
     * @param attemptId request identifier being decided
     * @param request decision code validated by the application service
     * @return updated attempt state
     */
    @PostMapping("/access-attempts/{attemptId}/decision")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminAccessAttemptDTO>> decide(
            @PathVariable UUID attemptId,
            @RequestBody AdminAccessDecisionRequestDTO request) {
        AdminAccessAttemptDTO response = adminAccessService.decide(
                authenticatedUserId(),
                attemptId,
                request.getDecision());
        return ResponseEntity.ok(ApiResponse.success("Admin access decision registered.", response));
    }

    /**
     * Lists registered administrator devices and their status.
     *
     * @return device identifiers and lifecycle statuses visible to the authenticated administrator
     */
    @GetMapping("/devices")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<AdminAuthenticatedDeviceDTO>>> devices() {
        return ResponseEntity.ok(ApiResponse.success(
                "Admin devices retrieved.",
                adminAccessService.devices(authenticatedUserId())));
    }

    /**
     * Blocks a registered administrator device from future authentication.
     *
     * @param deviceId stable device identifier to block
     * @return updated device status
     */
    @PostMapping("/devices/{deviceId}/block")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminAuthenticatedDeviceDTO>> blockDevice(@PathVariable String deviceId) {
        return ResponseEntity.ok(ApiResponse.success(
                "Admin device blocked.",
                adminAccessService.changeDeviceStatus(
                        authenticatedUserId(),
                        deviceId,
                        AdminAccessDeviceStatus.BLOCKED)));
    }

    /**
     * Revokes a registered administrator device and its trust relationship.
     *
     * @param deviceId stable device identifier to revoke
     * @return updated device status
     */
    @PostMapping("/devices/{deviceId}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AdminAuthenticatedDeviceDTO>> revokeDevice(@PathVariable String deviceId) {
        return ResponseEntity.ok(ApiResponse.success(
                "Admin device revoked.",
                adminAccessService.changeDeviceStatus(
                        authenticatedUserId(),
                        deviceId,
                        AdminAccessDeviceStatus.REVOKED)));
    }

    /** Resolves the authenticated principal to a persisted user identifier or rejects anonymous access. */
    private Long authenticatedUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getName())) {
            throw new AuthExceptions.InvalidCredentials("Not authenticated.");
        }
        return Long.parseLong(auth.getName());
    }

    /**
     * Extracts the first forwarded address when present, otherwise the servlet peer address.
     * The trusted-proxy configuration must ensure forwarding headers cannot be forged by clients.
     *
     * @param request current servlet request
     * @return address string used as an audit and risk signal
     */
    private String clientAddress(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
