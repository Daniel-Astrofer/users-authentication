package com.kerosene.auth.application.service.devicebinding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.common.infra.logging.LogDomain;
import com.kerosene.common.infra.logging.LogSanitizer;

/**
 * Tracks signature-counter replay failures per credential and applies a short soft-lock
 * after repeated failures (clone / desync signal — not "link a new passkey").
 */
@Service
public class DeviceCredentialReplayGuard {

    private static final Logger log = LoggerFactory.getLogger(DeviceCredentialReplayGuard.class);

    private static final String FAIL_PREFIX = "device_cred_replay_fail:";
    private static final String LOCK_PREFIX = "device_cred_replay_lock:";

    private final RedisServicer redisService;
    private final int failureThreshold;
    private final long failureWindowSeconds;
    private final long lockSeconds;

    /**
     * Creates a Redis-backed replay-failure counter and soft-lock policy.
     * Invalid non-positive configuration values fall back to the documented defaults.
     *
     * @param redisService Redis operations for failure counters and lock markers
     * @param failureThreshold consecutive failures required before a lock is set
     * @param failureWindowSeconds lifetime of the failure counter before it expires
     * @param lockSeconds duration of a soft-lock after the threshold is reached
     */
    public DeviceCredentialReplayGuard(
            RedisServicer redisService,
            @Value("${kerosene.auth.device-cred.replay-failure-threshold:3}") int failureThreshold,
            @Value("${kerosene.auth.device-cred.replay-failure-window-seconds:900}") long failureWindowSeconds,
            @Value("${kerosene.auth.device-cred.replay-lock-seconds:1200}") long lockSeconds) {
        this.redisService = redisService;
        this.failureThreshold = failureThreshold > 0 ? failureThreshold : 3;
        this.failureWindowSeconds = failureWindowSeconds > 0 ? failureWindowSeconds : 900L;
        this.lockSeconds = lockSeconds > 0 ? lockSeconds : 1200L;
    }

    /**
     * Returns the configured duration of a replay soft-lock.
     *
     * @return duration in seconds
     */
    public long lockSeconds() {
        return lockSeconds;
    }

    /**
     * Returns the configured failure threshold.
     *
     * @return failures required to activate the soft-lock
     */
    public int failureThreshold() {
        return failureThreshold;
    }

    /**
     * Checks whether Redis contains a soft-lock marker for the account and credential pair.
     * Invalid or absent identifiers are treated as not locked.
     *
     * @param userId account identifier
     * @param credentialRef privacy-preserving credential reference
     * @return true while a lock marker exists
     */
    public boolean isLocked(Long userId, String credentialRef) {
        if (userId == null || credentialRef == null || credentialRef.isBlank()) {
            return false;
        }
        return redisService.getValue(lockKey(userId, credentialRef)) != null;
    }

    /**
     * Increments the credential's failure counter and creates a timed soft-lock at the threshold.
     * The counter expires after the configured failure window; reaching the threshold clears it and
     * stores a separate lock marker for the configured lock duration.
     *
     * @param userId account identifier
     * @param credentialRef privacy-preserving credential reference
     * @param factorKind label identifying the credential factor for audit logs
     * @return true when this failure activates the soft-lock
     */
    public boolean recordReplayFailure(Long userId, String credentialRef, String factorKind) {
        if (userId == null || credentialRef == null || credentialRef.isBlank()) {
            return false;
        }
        String failKey = failKey(userId, credentialRef);
        Long count = redisService.increment(failKey);
        if (count == null) {
            count = 1L;
        }
        if (count == 1L) {
            redisService.expire(failKey, failureWindowSeconds);
        }
        log.warn(
                LogDomain.AUTH,
                "event=DEVICE_CREDENTIAL_REPLAY_FAILURE userId={} credentialRef={} factor={} count={}/{}",
                userId,
                credentialRef,
                factorKind,
                count,
                failureThreshold);

        if (count >= failureThreshold) {
            redisService.setValue(lockKey(userId, credentialRef), "1", lockSeconds);
            redisService.deleteValue(failKey);
            log.error(
                    LogDomain.AUTH,
                    "event=DEVICE_CREDENTIAL_REPLAY_SOFT_LOCK userId={} credentialRef={} factor={} lockSeconds={}",
                    userId,
                    credentialRef,
                    factorKind,
                    lockSeconds);
            return true;
        }
        return false;
    }

    /**
     * Clears the accumulated failure counter without removing an existing lock marker.
     *
     * @param userId account identifier
     * @param credentialRef privacy-preserving credential reference
     */
    public void clearFailures(Long userId, String credentialRef) {
        if (userId == null || credentialRef == null || credentialRef.isBlank()) {
            return;
        }
        redisService.deleteValue(failKey(userId, credentialRef));
    }

    /**
     * Produces a log-safe fingerprint reference for raw credential identifier bytes.
     *
     * @param credentialId credential identifier bytes
     * @return fingerprint reference, or {@code unknown} for absent input
     */
    public static String credentialRefFromBytes(byte[] credentialId) {
        if (credentialId == null || credentialId.length == 0) {
            return "unknown";
        }
        return LogSanitizer.fingerprint(credentialId);
    }

    /**
     * Trims and fingerprints a credential identifier string for Redis keys and logs.
     *
     * @param credentialId credential identifier
     * @return fingerprint reference, or {@code unknown} for absent input
     */
    public static String credentialRefFromString(String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            return "unknown";
        }
        return LogSanitizer.fingerprint(credentialId.trim().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Builds the Redis key for the expiring failure counter. */
    private static String failKey(Long userId, String credentialRef) {
        return FAIL_PREFIX + userId + ":" + credentialRef;
    }

    /** Builds the Redis key for the timed replay soft-lock marker. */
    private static String lockKey(Long userId, String credentialRef) {
        return LOCK_PREFIX + userId + ":" + credentialRef;
    }
}
