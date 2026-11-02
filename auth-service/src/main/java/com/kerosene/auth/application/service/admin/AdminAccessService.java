package com.kerosene.auth.application.service.admin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.jpa.AdminAccessAttemptRepository;
import com.kerosene.auth.application.infra.persistence.jpa.AdminAccessDeviceRepository;
import com.kerosene.auth.application.infra.persistence.jpa.AdminAccessEventRepository;
import com.kerosene.auth.application.infra.persistence.jpa.AdminKeyRepository;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.service.authentication.contracts.LoginVerifier;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.AdminAccessAttemptDTO;
import com.kerosene.auth.dto.AdminAuthenticatedDeviceDTO;
import com.kerosene.auth.dto.AdminKeyCreateRequestDTO;
import com.kerosene.auth.dto.AdminKeyStatusDTO;
import com.kerosene.auth.dto.AdminLoginRequestDTO;
import com.kerosene.auth.dto.AdminLoginResponseDTO;
import com.kerosene.auth.dto.UserDTO;
import com.kerosene.auth.model.entity.AdminAccessAttemptEntity;
import com.kerosene.auth.model.entity.AdminAccessDeviceEntity;
import com.kerosene.auth.model.entity.AdminAccessEventEntity;
import com.kerosene.auth.model.entity.AdminKeyEntity;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.auth.model.enums.AdminAccessAttemptStatus;
import com.kerosene.auth.model.enums.AdminAccessDeviceStatus;
import com.kerosene.auth.model.enums.AdminAccessEventStatus;
import com.kerosene.auth.model.enums.AdminKeyStatus;
import com.kerosene.auth.model.enums.UserRole;
import com.kerosene.common.infra.logging.LogSanitizer;
import com.kerosene.notification.l10n.NotificationMessageKey;
import com.kerosene.notification.l10n.NotificationMessages;
import com.kerosene.notification.model.NotificationKind;
import com.kerosene.notification.model.NotificationSeverity;
import com.kerosene.notification.service.NotificationService;

/**
 * Coordinates administrator login approval, key enrollment, device trust, and audit recording.
 * Login attempts are transactionally persisted and bound to a client-context fingerprint until
 * an active mobile device approves them or the configured five-minute attempt expires.
 */
@Service
public class AdminAccessService {

    private static final Logger log = LoggerFactory.getLogger(AdminAccessService.class);
    private static final int MAX_TEXT = 512;
    private static final long ATTEMPT_TTL_MINUTES = 5;

    private final LoginVerifier loginVerifier;
    private final JwtServicer jwtServicer;
    private final UserRepository userRepository;
    private final AdminKeyRepository adminKeyRepository;
    private final AdminAccessDeviceRepository deviceRepository;
    private final AdminAccessAttemptRepository attemptRepository;
    private final AdminAccessEventRepository eventRepository;
    private final NotificationService notificationService;

    /**
     * Wires the identity, persistence, token, audit, and notification boundaries used by admin access.
     *
     * @param loginVerifier verifies submitted account credentials
     * @param jwtServicer issues the administrator token after successful mobile approval
     * @param userRepository resolves the account and role
     * @param adminKeyRepository persists administrator key hashes and lifecycle state
     * @param deviceRepository persists device enrollment and trust status
     * @param attemptRepository persists and locks pending access attempts
     * @param eventRepository records security-relevant access outcomes
     * @param notificationService notifies the mobile account about a pending attempt
     */
    public AdminAccessService(
            LoginVerifier loginVerifier,
            JwtServicer jwtServicer,
            UserRepository userRepository,
            AdminKeyRepository adminKeyRepository,
            AdminAccessDeviceRepository deviceRepository,
            AdminAccessAttemptRepository attemptRepository,
            AdminAccessEventRepository eventRepository,
            NotificationService notificationService) {
        this.loginVerifier = loginVerifier;
        this.jwtServicer = jwtServicer;
        this.userRepository = userRepository;
        this.adminKeyRepository = adminKeyRepository;
        this.deviceRepository = deviceRepository;
        this.attemptRepository = attemptRepository;
        this.eventRepository = eventRepository;
        this.notificationService = notificationService;
    }

    /**
     * Verifies credentials and the configured admin-key proof, then creates a pending mobile approval.
     * The attempt stores a fingerprint of the address and the sanitized user-agent context for poll binding;
     * a blocked or revoked device is rejected before an attempt is created.
     *
     * @param request credentials, admin-key proof, and device metadata submitted by the client
     * @param remoteAddress network address supplied by the trusted HTTP boundary
     * @param userAgentHeader request user-agent used when client metadata omits it
     * @return pending challenge identifier and expiry; no session token is issued yet
     * @throws AuthExceptions.StructuredAuthException for non-admin roles, missing/invalid keys, or blocked devices
     */
    @Transactional
    public AdminLoginResponseDTO startLogin(
            AdminLoginRequestDTO request,
            String remoteAddress,
            String userAgentHeader) {
        UserDataBase user = authenticateCredentials(request);
        String deviceId = stableDeviceId(request, remoteAddress, userAgentHeader);
        String browser = safe(firstText(request.getBrowser(), "Navegador"));
        String userAgent = safe(firstText(request.getUserAgent(), userAgentHeader, request.getPlatform()));
        String ipFingerprint = LogSanitizer.fingerprint(remoteAddress);

        if (user.getRole() != UserRole.ADMIN) {
            recordEvent(user.getId(), deviceId, browser, userAgent, ipFingerprint, AdminAccessEventStatus.DENIED,
                    "user_not_admin");
            throw new AuthExceptions.StructuredAuthException(
                    "Acesso administrativo restrito.",
                    HttpStatus.FORBIDDEN,
                    "ADMIN_ROLE_REQUIRED",
                    null);
        }

        AdminKeyEntity activeKey = adminKeyRepository
                .findFirstByUserIdAndStatusOrderByCreatedAtDesc(user.getId(), AdminKeyStatus.ACTIVE)
                .orElseThrow(() -> {
                    recordEvent(user.getId(), deviceId, browser, userAgent, ipFingerprint, AdminAccessEventStatus.DENIED,
                            "admin_key_missing");
                    return new AuthExceptions.StructuredAuthException(
                            "Chave de administracao nao configurada.",
                            HttpStatus.UNAUTHORIZED,
                            "ADMIN_KEY_REQUIRED",
                            null);
                });

        if (!constantTimeEquals(normalizeHash(request.getAdminKeyProof()), activeKey.getKeyMaterialHash())) {
            recordEvent(user.getId(), deviceId, browser, userAgent, ipFingerprint, AdminAccessEventStatus.DENIED,
                    "admin_key_invalid");
            throw new AuthExceptions.StructuredAuthException(
                    "Credenciais administrativas invalidas.",
                    HttpStatus.UNAUTHORIZED,
                    "ADMIN_KEY_INVALID",
                    null);
        }

        AdminAccessDeviceEntity device = upsertDevice(user, deviceId, request.getDeviceName(), browser, userAgent);
        if (device.getStatus() == AdminAccessDeviceStatus.BLOCKED
                || device.getStatus() == AdminAccessDeviceStatus.REVOKED) {
            recordEvent(user.getId(), deviceId, browser, userAgent, ipFingerprint, AdminAccessEventStatus.BLOCKED,
                    "device_blocked");
            throw new AuthExceptions.StructuredAuthException(
                    "Este dispositivo esta bloqueado para acesso administrativo.",
                    HttpStatus.LOCKED,
                    "ADMIN_DEVICE_BLOCKED",
                    null);
        }

        LocalDateTime now = LocalDateTime.now();
        AdminAccessAttemptEntity attempt = new AdminAccessAttemptEntity();
        attempt.setUser(user);
        attempt.setDevice(device);
        attempt.setStatus(AdminAccessAttemptStatus.PENDING);
        attempt.setBrowser(browser);
        attempt.setUserAgent(userAgent);
        attempt.setIpFingerprint(ipFingerprint);
        attempt.setRequestedAt(now);
        attempt.setExpiresAt(now.plusMinutes(ATTEMPT_TTL_MINUTES));
        attempt = attemptRepository.save(attempt);

        notifyMobile(user, attempt);

        return new AdminLoginResponseDTO(
                "PENDING",
                true,
                attempt.getId(),
                attempt.getExpiresAt(),
                null,
                "Aguardando autorizacao no app mobile.");
    }

    /**
     * Reads a pending attempt under a write lock and redeems an approval exactly once.
     * On approval it activates the device, marks the attempt redeemed, and issues an admin JWT;
     * expired or still-pending attempts never receive a token.
     *
     * @param attemptId challenge identifier returned by {@link #startLogin(AdminLoginRequestDTO, String, String)}
     * @param remoteAddress polling client's network address, fingerprinted and compared to the challenge
     * @param userAgentHeader polling client's user-agent, compared to the challenge context
     * @return current challenge state and a token only when mobile approval was redeemed
     * @throws AuthExceptions.StructuredAuthException when the attempt is absent or client context differs
     */
    @Transactional
    public AdminLoginResponseDTO pollLogin(UUID attemptId, String remoteAddress, String userAgentHeader) {
        AdminAccessAttemptEntity attempt = attemptRepository.findForPollingById(attemptId)
                .orElseThrow(() -> new AuthExceptions.StructuredAuthException(
                        "Tentativa administrativa nao encontrada.",
                        HttpStatus.NOT_FOUND,
                        "ADMIN_ATTEMPT_NOT_FOUND",
                        null));

        validatePollingContext(attempt, remoteAddress, userAgentHeader);

        if (attempt.getStatus() == AdminAccessAttemptStatus.PENDING
                && attempt.getExpiresAt().isBefore(LocalDateTime.now())) {
            attempt.setStatus(AdminAccessAttemptStatus.EXPIRED);
            attempt.setDecidedAt(LocalDateTime.now());
            attemptRepository.save(attempt);
        }

        if (attempt.getStatus() == AdminAccessAttemptStatus.APPROVED) {
            attempt.getDevice().setStatus(AdminAccessDeviceStatus.ACTIVE);
            attempt.getDevice().setLastAccessAt(LocalDateTime.now());
            attempt.setStatus(AdminAccessAttemptStatus.REDEEMED);
            attemptRepository.save(attempt);
            deviceRepository.save(attempt.getDevice());
            String token = attempt.getUser().getId() + " "
                    + jwtServicer.generateTokenAtCredentialEpoch(attempt.getUser().getId(), List.of(UserRole.ADMIN.name()), attempt.getUser().getCredentialEpoch());
            return new AdminLoginResponseDTO(
                    "APPROVED",
                    false,
                    attempt.getId(),
                    attempt.getExpiresAt(),
                    token,
                    "Acesso administrativo registrado.");
        }

        return new AdminLoginResponseDTO(
                attempt.getStatus().name(),
                attempt.getStatus() == AdminAccessAttemptStatus.PENDING,
                attempt.getId(),
                attempt.getExpiresAt(),
                null,
                statusMessage(attempt.getStatus()));
    }

    /**
     * Recomputes poll context signals and rejects a request that differs from the challenge context.
     *
     * @param attempt persisted challenge containing the expected fingerprints
     * @param remoteAddress current request address
     * @param userAgentHeader current request user-agent
     * @throws AuthExceptions.StructuredAuthException when either fingerprint differs
     */
    private void validatePollingContext(
            AdminAccessAttemptEntity attempt,
            String remoteAddress,
            String userAgentHeader) {
        String expectedIpFingerprint = safeId(attempt.getIpFingerprint());
        String requestIpFingerprint = LogSanitizer.fingerprint(remoteAddress);
        String expectedUserAgent = safe(attempt.getUserAgent());
        String requestUserAgent = safe(userAgentHeader);

        if (!constantTimeEquals(expectedIpFingerprint, requestIpFingerprint)
                || !constantTimeEquals(expectedUserAgent, requestUserAgent)) {
            throw new AuthExceptions.StructuredAuthException(
                    "Contexto da tentativa administrativa nao confere.",
                    HttpStatus.FORBIDDEN,
                    "ADMIN_ATTEMPT_CONTEXT_MISMATCH",
                    null);
        }
    }

    /**
     * Lists non-expired pending attempts for one administrator, newest first.
     *
     * @param userId authenticated administrator account identifier
     * @return pending challenge summaries eligible for a decision
     */
    @Transactional(readOnly = true)
    public List<AdminAccessAttemptDTO> pendingAttempts(Long userId) {
        return attemptRepository
                .findByUserIdAndStatusAndExpiresAtAfterOrderByRequestedAtDesc(
                        userId,
                        AdminAccessAttemptStatus.PENDING,
                        LocalDateTime.now())
                .stream()
                .map(this::toAttemptDTO)
                .toList();
    }

    /**
     * Records an administrator's decision for an account-scoped pending attempt.
     * Only {@code APPROVE} and {@code ALLOW} are approvals; other values block the request and device.
     * Expired attempts are marked expired and returned without applying the supplied decision.
     *
     * @param userId authenticated administrator account identifier
     * @param attemptId pending attempt identifier
     * @param decision requested approval or denial code
     * @return updated attempt status
     * @throws AuthExceptions.StructuredAuthException when the attempt is absent or belongs to another account
     */
    @Transactional
    public AdminAccessAttemptDTO decide(Long userId, UUID attemptId, String decision) {
        AdminAccessAttemptEntity attempt = attemptRepository.findByIdAndUserId(attemptId, userId)
                .orElseThrow(() -> new AuthExceptions.StructuredAuthException(
                        "Tentativa administrativa nao encontrada.",
                        HttpStatus.NOT_FOUND,
                        "ADMIN_ATTEMPT_NOT_FOUND",
                        null));

        if (attempt.getExpiresAt().isBefore(LocalDateTime.now())) {
            attempt.setStatus(AdminAccessAttemptStatus.EXPIRED);
            attempt.setDecidedAt(LocalDateTime.now());
            attemptRepository.save(attempt);
            return toAttemptDTO(attempt);
        }

        boolean approve = "APPROVE".equalsIgnoreCase(decision) || "ALLOW".equalsIgnoreCase(decision);
        AdminAccessDeviceEntity device = attempt.getDevice();
        attempt.setDecidedAt(LocalDateTime.now());

        if (approve) {
            attempt.setStatus(AdminAccessAttemptStatus.APPROVED);
            device.setStatus(AdminAccessDeviceStatus.ACTIVE);
            device.setLastAccessAt(LocalDateTime.now());
            recordEvent(userId, device.getDeviceId(), attempt.getBrowser(), attempt.getUserAgent(),
                    attempt.getIpFingerprint(), AdminAccessEventStatus.APPROVED, "mobile_approved");
        } else {
            attempt.setStatus(AdminAccessAttemptStatus.BLOCKED);
            device.setStatus(AdminAccessDeviceStatus.BLOCKED);
            recordEvent(userId, device.getDeviceId(), attempt.getBrowser(), attempt.getUserAgent(),
                    attempt.getIpFingerprint(), AdminAccessEventStatus.BLOCKED, "mobile_blocked");
        }

        deviceRepository.save(device);
        return toAttemptDTO(attemptRepository.save(attempt));
    }

    /**
     * Replaces active administrator key records with a normalized verifier for the new enrollment.
     * Existing active keys are revoked in the same transaction; only the verifier and its fingerprint
     * are persisted, never a raw signing secret.
     *
     * @param userId account receiving the key enrollment
     * @param request write-only key verifier and optional device-install binding
     * @return non-secret status and fingerprint of the newly active key
     * @throws AuthExceptions.InvalidCredentials when the account does not exist
     * @throws AuthExceptions.StructuredAuthException when the normalized verifier length is outside 32..128
     */
    @Transactional
    public AdminKeyStatusDTO createOrRotateKey(Long userId, AdminKeyCreateRequestDTO request) {
        UserDataBase user = requireUser(userId);
        String hash = normalizeHash(request.getKeyMaterialHash());
        if (hash.length() < 32 || hash.length() > 128) {
            throw new AuthExceptions.StructuredAuthException(
                    "Material de chave administrativa invalido.",
                    HttpStatus.BAD_REQUEST,
                    "ADMIN_KEY_HASH_INVALID",
                    null);
        }

        LocalDateTime now = LocalDateTime.now();
        List<AdminKeyEntity> existingKeys = adminKeyRepository.findByUserIdAndStatus(userId, AdminKeyStatus.ACTIVE);
        existingKeys.forEach(existing -> {
            existing.setStatus(AdminKeyStatus.REVOKED);
            existing.setRevokedAt(now);
            existing.setRotatedAt(now);
        });
        if (!existingKeys.isEmpty()) {
            adminKeyRepository.saveAll(existingKeys);
        }

        AdminKeyEntity key = new AdminKeyEntity();
        key.setUser(user);
        key.setKeyMaterialHash(hash);
        key.setKeyFingerprint(LogSanitizer.fingerprint(hash));
        key.setDeviceInstallId(safeId(request.getDeviceInstallId()));
        key.setStatus(AdminKeyStatus.ACTIVE);
        key = adminKeyRepository.save(key);

        return toKeyStatus(key);
    }

    /**
     * Returns active key metadata without revealing the stored verifier.
     *
     * @param userId account whose active key is queried
     * @return active key summary or an explicit MISSING status
     */
    @Transactional(readOnly = true)
    public AdminKeyStatusDTO keyStatus(Long userId) {
        return adminKeyRepository.findFirstByUserIdAndStatusOrderByCreatedAtDesc(userId, AdminKeyStatus.ACTIVE)
                .map(this::toKeyStatus)
                .orElse(new AdminKeyStatusDTO(false, "MISSING", null, null, null));
    }

    /**
     * Revokes all active key records for the account and records their revocation time.
     *
     * @param userId account whose keys are revoked
     * @return non-secret revoked status and the operation timestamp
     */
    @Transactional
    public AdminKeyStatusDTO revokeKey(Long userId) {
        LocalDateTime now = LocalDateTime.now();
        List<AdminKeyEntity> active = adminKeyRepository.findByUserIdAndStatus(userId, AdminKeyStatus.ACTIVE);
        active.forEach(key -> {
            key.setStatus(AdminKeyStatus.REVOKED);
            key.setRevokedAt(now);
        });
        if (!active.isEmpty()) {
            adminKeyRepository.saveAll(active);
        }
        return new AdminKeyStatusDTO(false, "REVOKED", null, null, now);
    }

    /**
     * Lists the administrator's enrolled devices, newest last-access first with unset times last.
     *
     * @param userId account whose devices are listed
     * @return device summaries including current trust status
     */
    @Transactional(readOnly = true)
    public List<AdminAuthenticatedDeviceDTO> devices(Long userId) {
        return deviceRepository.findByUserIdOrderByLastAccessAtDesc(userId)
                .stream()
                .sorted(Comparator.comparing(AdminAccessDeviceEntity::getLastAccessAt,
                        Comparator.nullsLast(Comparator.reverseOrder())))
                .map(this::toDeviceDTO)
                .toList();
    }

    /**
     * Changes one account-scoped device's trust state and refreshes its last-access timestamp.
     *
     * @param userId owning administrator account
     * @param deviceId stable device enrollment identifier
     * @param status target trust state
     * @return persisted device summary after the change
     * @throws AuthExceptions.StructuredAuthException when the device is not enrolled for this account
     */
    @Transactional
    public AdminAuthenticatedDeviceDTO changeDeviceStatus(Long userId, String deviceId, AdminAccessDeviceStatus status) {
        AdminAccessDeviceEntity device = deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new AuthExceptions.StructuredAuthException(
                        "Dispositivo administrativo nao encontrado.",
                        HttpStatus.NOT_FOUND,
                        "ADMIN_DEVICE_NOT_FOUND",
                        null));
        device.setStatus(status);
        device.setLastAccessAt(LocalDateTime.now());
        return toDeviceDTO(deviceRepository.save(device));
    }

    /**
     * Adapts admin credentials to the shared login verifier and clears password buffers afterwards.
     *
     * @param request login credentials; its password field is wiped before this method exits
     * @return authenticated persisted account
     */
    private UserDataBase authenticateCredentials(AdminLoginRequestDTO request) {
        UserDTO dto = new UserDTO();
        dto.setUsername(request.getUsername());
        dto.setPassword(request.getPassword());
        try {
            return loginVerifier.matcherWithoutDevice(dto);
        } finally {
            dto.setPassword(null);
            request.wipePassword();
        }
    }

    /**
     * Loads or creates an account-scoped device enrollment and refreshes its descriptive metadata.
     * Existing blocked or revoked states are preserved for the caller to reject.
     *
     * @param user account that owns the device
     * @param deviceId stable identifier derived from the request
     * @param deviceName optional label supplied by the client
     * @param browser bounded browser label
     * @param userAgent bounded user-agent description
     * @return persisted device enrollment with updated last-access time
     */
    private AdminAccessDeviceEntity upsertDevice(
            UserDataBase user,
            String deviceId,
            String deviceName,
            String browser,
            String userAgent) {
        AdminAccessDeviceEntity device = deviceRepository.findByUserIdAndDeviceId(user.getId(), deviceId)
                .orElseGet(AdminAccessDeviceEntity::new);
        device.setUser(user);
        device.setDeviceId(deviceId);
        device.setDeviceName(safe(firstText(deviceName, browser, "Sessao admin")));
        device.setBrowser(browser);
        device.setUserAgent(userAgent);
        if (device.getStatus() == null) {
            device.setStatus(AdminAccessDeviceStatus.PENDING);
        }
        device.setLastAccessAt(LocalDateTime.now());
        return deviceRepository.save(device);
    }

    /**
     * Sends a warning notification containing the pending challenge metadata to the user's mobile account.
     * Delivery failures are logged and do not roll back the already-persisted login attempt.
     *
     * @param user account to notify
     * @param attempt persisted challenge referenced by the notification
     */
    private void notifyMobile(UserDataBase user, AdminAccessAttemptEntity attempt) {
        try {
            notificationService.notifyUser(
                    user.getId(),
                    NotificationMessages.payload(
                            NotificationKind.SECURITY_ADMIN_ACCESS_ATTEMPT,
                            NotificationSeverity.WARNING,
                            NotificationMessageKey.SECURITY_ADMIN_ACCESS_ATTEMPT,
                            "/settings",
                            "admin_access_attempt",
                            attempt.getId().toString(),
                            Map.of(
                                    "attemptId", attempt.getId().toString(),
                                    "browser", safe(firstText(attempt.getBrowser(), "Navegador")),
                                    "device", safe(firstText(attempt.getDevice().getDeviceName(), "Sessao admin")),
                                    "requestedAt", attempt.getRequestedAt().toString(),
                                    "status", attempt.getStatus().name())));
        } catch (RuntimeException exception) {
            log.warn("Falha ao notificar tentativa admin para userId={}", user.getId(), exception);
        }
    }

    /**
     * Persists a sanitized audit event for an administrator access outcome.
     *
     * @param adminId account involved in the event
     * @param deviceId enrolled or attempted device identifier
     * @param browser browser metadata captured for the event
     * @param userAgent sanitized user-agent description
     * @param ipFingerprint one-way client address fingerprint
     * @param status access outcome
     * @param reason bounded internal reason code
     */
    private void recordEvent(
            Long adminId,
            String deviceId,
            String browser,
            String userAgent,
            String ipFingerprint,
            AdminAccessEventStatus status,
            String reason) {
        AdminAccessEventEntity event = new AdminAccessEventEntity();
        event.setAdminId(adminId);
        event.setDeviceId(safeId(deviceId));
        event.setBrowser(safe(browser));
        event.setSanitizedUserAgent(safe(userAgent));
        event.setIpFingerprint(safeId(ipFingerprint));
        event.setStatus(status);
        event.setReason(safe(reason));
        eventRepository.save(event);
    }

    /** Projects the persistence entity and its linked device into the API attempt response. */
    private AdminAccessAttemptDTO toAttemptDTO(AdminAccessAttemptEntity attempt) {
        AdminAccessDeviceEntity device = attempt.getDevice();
        return new AdminAccessAttemptDTO(
                attempt.getId(),
                attempt.getStatus().name(),
                device.getDeviceId(),
                device.getDeviceName(),
                attempt.getBrowser(),
                attempt.getUserAgent(),
                attempt.getIpFingerprint(),
                attempt.getRequestedAt(),
                attempt.getExpiresAt());
    }

    /** Projects device enrollment metadata without exposing persistence identifiers or key material. */
    private AdminAuthenticatedDeviceDTO toDeviceDTO(AdminAccessDeviceEntity device) {
        return new AdminAuthenticatedDeviceDTO(
                device.getDeviceId(),
                device.getDeviceName(),
                device.getBrowser(),
                device.getUserAgent(),
                device.getStatus().name(),
                device.getFirstAccessAt(),
                device.getLastAccessAt());
    }

    /** Projects key lifecycle metadata and the non-secret display fingerprint into an API response. */
    private AdminKeyStatusDTO toKeyStatus(AdminKeyEntity key) {
        return new AdminKeyStatusDTO(
                key.getStatus() == AdminKeyStatus.ACTIVE,
                key.getStatus().name(),
                key.getKeyFingerprint(),
                key.getCreatedAt(),
                key.getRevokedAt());
    }

    /**
     * Loads an account required for key enrollment or raises a structured not-found error.
     *
     * @param userId persisted account identifier
     * @return account entity
     * @throws AuthExceptions.StructuredAuthException when no row exists
     */
    private UserDataBase requireUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AuthExceptions.StructuredAuthException(
                        "Usuario autenticado nao encontrado.",
                        HttpStatus.NOT_FOUND,
                        "USER_NOT_FOUND",
                        null));
    }

    /** Compares normalized verifier strings through the JDK constant-time byte-array primitive. */
    private boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(
                normalizeHash(left).getBytes(StandardCharsets.UTF_8),
                normalizeHash(right).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Uses a bounded client device identifier when supplied, otherwise derives a stable fingerprint
     * from browser, user-agent, platform, and network address signals.
     *
     * @param request login request containing optional device metadata
     * @param remoteAddress observed client address used only as a fingerprint input
     * @param userAgentHeader HTTP user-agent fallback
     * @return sanitized identifier suitable for the device enrollment key
     */
    private String stableDeviceId(AdminLoginRequestDTO request, String remoteAddress, String userAgentHeader) {
        String declared = request.getDeviceId();
        if (hasText(declared) && declared.length() <= 128) {
            return safeId(declared);
        }
        String fingerprintBase = firstText(request.getBrowser(), "browser") + "|"
                + firstText(request.getUserAgent(), userAgentHeader, "user-agent") + "|"
                + firstText(request.getPlatform(), "platform") + "|"
                + firstText(remoteAddress, "ip");
        return LogSanitizer.fingerprint(fingerprintBase);
    }

    /** Maps a persisted attempt state to the user-facing polling response message. */
    private String statusMessage(AdminAccessAttemptStatus status) {
        return switch (status) {
            case PENDING -> "Aguardando autorizacao no app mobile.";
            case DENIED, BLOCKED -> "Acesso administrativo bloqueado no app mobile.";
            case EXPIRED -> "A tentativa de acesso expirou.";
            case REDEEMED -> "A tentativa de acesso administrativo ja foi utilizada.";
            case APPROVED -> "Acesso administrativo registrado.";
        };
    }

    /** Trims and lowercases a submitted key verifier; null becomes an empty value for validation. */
    private String normalizeHash(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    /** Returns the first non-null, non-blank candidate, or the empty string. */
    private String firstText(String... values) {
        for (String value : values) {
            if (hasText(value)) {
                return value;
            }
        }
        return "";
    }

    /** Checks whether a string contains any non-whitespace character. */
    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    /** Sanitizes an identifier and fingerprints it when it exceeds the storage bound. */
    private String safeId(String value) {
        String sanitized = safe(value);
        return sanitized.length() > 128 ? LogSanitizer.fingerprint(sanitized) : sanitized;
    }

    /** Replaces control whitespace, trims a value, and truncates it to the audit text limit. */
    private String safe(String value) {
        if (value == null) {
            return "";
        }
        String sanitized = value.replaceAll("[\\r\\n\\t]", " ").trim();
        return sanitized.length() > MAX_TEXT ? sanitized.substring(0, MAX_TEXT) : sanitized;
    }
}
