package com.kerosene.auth.application.orchestrator.recovery;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.kerosene.auth.application.service.recovery.RecoveryCredentialRotator;
import com.kerosene.auth.application.service.recovery.RecoveryCredentialRotator.RotationResult;
import com.kerosene.auth.application.service.recovery.RecoverySecretProtector;
import com.kerosene.auth.application.service.recovery.RecoverySecretProtector.PreparedRecoverySecrets;
import com.kerosene.auth.application.service.recovery.RecoveryStateStore;
import com.kerosene.auth.application.service.recovery.RecoveryStateStore.StoredRecoverySession;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.application.service.recovery.start.chain.EmergencyRecoveryStartChain;
import com.kerosene.auth.dto.EmergencyRecoveryFinishRequest;
import com.kerosene.auth.dto.EmergencyRecoveryFinishResponse;
import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;
import com.kerosene.auth.dto.EmergencyRecoveryStartResponse;
import com.kerosene.auth.dto.EmergencyRecoveryState;
import com.kerosene.common.infra.logging.LogSanitizer;

/** Coordinates emergency credential recovery from initial proof checks through credential rotation. */
@Component
public class EmergencyRecoveryUseCase {

    /** Logger for recovery lifecycle events; user identifiers are fingerprinted. */
    private static final Logger log = LoggerFactory.getLogger(EmergencyRecoveryUseCase.class);

    /** Validates the ordered set of recovery proofs and constructs a start context. */
    private final EmergencyRecoveryStartChain recoveryStartChain;
    /** Protects replacement passphrase/TOTP material and recovers it during completion. */
    private final RecoverySecretProtector secretProtector;
    /** Persists and consumes expiring emergency recovery sessions. */
    private final RecoveryStateStore stateStore;
    /** Validates completion data and rotates existing authentication credentials. */
    private final RecoveryCredentialRotator credentialRotator;
    /** Bounds challenge preparation, including invalid guesses, per proven recovery session. */
    private final com.kerosene.auth.application.service.recovery.RecoveryRateLimitService rateLimitService;

    /** Minimum number of backup recovery-code hashes required by the configured start chain. */
    @Value("${auth.recovery.required-backup-codes:3}")
    private int requiredRecoveryCodes;

    /** Creates the emergency recovery coordinator.
     * @param recoveryStartChain proof-validation chain for recovery initiation
     * @param secretProtector replacement secret protection service
     * @param stateStore recovery session persistence boundary
     * @param credentialRotator credential replacement operation
     */
    public EmergencyRecoveryUseCase(EmergencyRecoveryStartChain recoveryStartChain,
            RecoverySecretProtector secretProtector,
            RecoveryStateStore stateStore,
            RecoveryCredentialRotator credentialRotator,
            com.kerosene.auth.application.service.recovery.RecoveryRateLimitService rateLimitService) {
        this.recoveryStartChain = recoveryStartChain;
        this.secretProtector = secretProtector;
        this.stateStore = stateStore;
        this.credentialRotator = credentialRotator;
        this.rateLimitService = rateLimitService;
    }

    /**
     * Validates recovery proofs, protects replacement secrets, persists an expiring recovery
     * session, and returns its passkey challenge and TOTP setup material.
     *
     * @param request user-submitted recovery proofs and replacement passphrase
     * @param clientFingerprint stable client/device reference for risk policy
     * @return session ID, enrollment URI, challenge, expiry, and required recovery-code count
     */
    public EmergencyRecoveryStartResponse start(EmergencyRecoveryStartRequest request, String clientFingerprint) {
        EmergencyRecoveryStartContext context = recoveryStartChain.handle(request, clientFingerprint);
        PreparedRecoverySecrets secrets = secretProtector.prepare(context.normalizedUsername(), request.getNewPassphrase());
        StoredRecoverySession session = stateStore.createSession(
                context,
                secrets.hashedPassphrase(),
                secrets.encryptedTotpSecret());

        log.warn("[Recovery] Emergency recovery initiated for userRef={} using {} recovery codes.",
                LogSanitizer.fingerprint(context.normalizedUsername()), context.matchedRecoveryCodeHashes().size());

        var response = new EmergencyRecoveryStartResponse(
                session.sessionId(),
                secrets.otpUri(),
                session.passkeyChallenge(),
                session.expiresInSeconds(),
                requiredRecoveryCodes);
        response.setDeviceKeyRecoverySupported(true);
        return response;
    }

    /** Prepares the short-lived enrollment proof only when the new authenticator is ready. */
    public com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse prepareDeviceKeyChallenge(
            com.kerosene.auth.dto.EmergencyRecoveryDeviceKeyChallengeRequest request) {
        if (request == null || request.getRecoverySessionId() == null || request.getRecoverySessionId().isBlank()
                || request.getRecoverySessionId().length() > 128
                || request.getTotpCode() == null || !request.getTotpCode().matches("[0-9]{6}")) {
            throw new IllegalArgumentException("A recovery session and fresh authenticator code are required.");
        }
        var state = stateStore.readRequired(request.getRecoverySessionId());
        rateLimitService.enforceDeviceKeyChallengeAttempt(request.getRecoverySessionId());
        return credentialRotator.prepareDeviceKeyChallenge(state,
                secretProtector.recoverTotpSecret(state.getEncryptedTotpSecret()), request.getTotpCode());
    }

    /**
     * Validates completion input, consumes the required one-time recovery session, and rotates
     * credentials within a database transaction.
     *
     * @param request session identifier and final recovery proof
     * @return account name and newly issued backup codes
     */
    @Transactional
    public EmergencyRecoveryFinishResponse finish(EmergencyRecoveryFinishRequest request) {
        credentialRotator.validateFinishRequest(request);

        EmergencyRecoveryState state = stateStore.consumeRequired(request.getRecoverySessionId());
        String totpSecret = secretProtector.recoverTotpSecret(state.getEncryptedTotpSecret());
        RotationResult result = credentialRotator.rotate(state, request, totpSecret);

        log.warn("[Recovery] Emergency recovery finished for userRef={}. Old credentials rotated.",
                LogSanitizer.fingerprint(result.username()));
        var response = new EmergencyRecoveryFinishResponse(result.username(), result.newBackupCodes());
        response.setDeviceKeyCredentialId(result.deviceKeyCredentialId());
        return response;
    }

    /**
     * Derives a deterministic opaque fingerprint from the first forwarded address (when supplied),
     * remote address, and user agent. If SHA-256 is unavailable, returns a sanitized raw composite.
     *
     * @param request servlet request used to derive client metadata
     * @return URL-safe Base64 fingerprint or sanitized fallback
     */
    public static String buildClientFingerprint(jakarta.servlet.http.HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        String clientIp = forwarded != null && !forwarded.isBlank()
                ? forwarded.split(",")[0].trim()
                : request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String raw = clientIp + "|" + (userAgent == null ? "-" : userAgent);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return raw.replaceAll("[^a-zA-Z0-9_.:-]", "_");
        }
    }
}
