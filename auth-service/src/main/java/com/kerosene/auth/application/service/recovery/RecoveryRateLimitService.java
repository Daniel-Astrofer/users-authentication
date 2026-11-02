package com.kerosene.auth.application.service.recovery;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.redis.contracts.RedisContract;

/** Enforces client- and username-scoped limits for starting emergency credential recovery. */
@Service
public class RecoveryRateLimitService {

    /** Redis state and counter boundary. */
    private final RedisContract redisContract;

    /** Duration of the client attempt-count window. */
    @Value("${auth.recovery.client-window-seconds:600}")
    private long clientWindowSeconds;

    /** Maximum client start attempts before a block is written. */
    @Value("${auth.recovery.client-max-attempts:6}")
    private long clientMaxAttempts;

    /** Duration of the username failure-count window. */
    @Value("${auth.recovery.username-window-seconds:1800}")
    private long usernameWindowSeconds;

    /** Username failure count that activates both username and client blocks. */
    @Value("${auth.recovery.username-max-attempts:4}")
    private long usernameMaxAttempts;

    /** Duration of temporary blocks written after exceeding configured limits. */
    @Value("${auth.recovery.block-seconds:1800}")
    private long recoveryBlockSeconds;

    /** Creates the recovery throttle service. */
    /** @param redisContract Redis counters and block-marker operations */
    public RecoveryRateLimitService(RedisContract redisContract) {
        this.redisContract = redisContract;
    }

    /** Rejects active client/user blocks, then counts client starts in a fixed expiry window. */
    /** @param normalizedUsername canonical account username */
    /** @param clientFingerprint opaque client/device fingerprint */
    /** @throws AuthExceptions.RecoveryRateLimitedException when blocked or over the attempt limit */
    public void enforceStartAttempt(String normalizedUsername, String clientFingerprint) {
        String clientKey = "auth:recovery:attempts:client:" + clientFingerprint;
        String clientBlockKey = "auth:recovery:block:client:" + clientFingerprint;
        String userBlockKey = "auth:recovery:block:user:" + normalizedUsername;

        if (redisContract.getValue(clientBlockKey) != null || redisContract.getValue(userBlockKey) != null) {
            throw new AuthExceptions.RecoveryRateLimitedException(
                    "Emergency recovery is temporarily blocked for this client or username.");
        }

        Long clientAttempts = redisContract.increment(clientKey);
        // null = Redis degraded; fail-open rather than 500 the recovery start.
        if (clientAttempts == null) {
            return;
        }
        if (clientAttempts == 1L) {
            redisContract.expire(clientKey, clientWindowSeconds);
        }
        if (clientAttempts > clientMaxAttempts) {
            redisContract.setValue(clientBlockKey, "1", recoveryBlockSeconds);
            throw new AuthExceptions.RecoveryRateLimitedException(
                    "Emergency recovery is temporarily blocked for this client.");
        }
    }

    /** Bounds new authenticator guesses and challenge issuance within one already-proven recovery session. */
    public void enforceDeviceKeyChallengeAttempt(String recoverySessionId) {
        Long attempts = redisContract.incrementWithExpire("auth:recovery:device-key:" + recoverySessionId,
                clientWindowSeconds);
        if (attempts == null || attempts < 1 || attempts > clientMaxAttempts) {
            throw new AuthExceptions.RecoveryRateLimitedException("Recovery enrollment challenge limit exceeded.");
        }
    }

    /** Counts failed recovery proofs by username and blocks both username and client at the threshold. */
    /** @param normalizedUsername canonical account username */
    /** @param clientFingerprint client/device fingerprint to block with the account */
    public void registerFailure(String normalizedUsername, String clientFingerprint) {
        String userAttemptsKey = "auth:recovery:attempts:user:" + normalizedUsername;
        Long userAttempts = redisContract.increment(userAttemptsKey);
        if (userAttempts == null) {
            return;
        }
        if (userAttempts == 1L) {
            redisContract.expire(userAttemptsKey, usernameWindowSeconds);
        }
        if (userAttempts >= usernameMaxAttempts) {
            redisContract.setValue("auth:recovery:block:user:" + normalizedUsername, "1", recoveryBlockSeconds);
            redisContract.setValue("auth:recovery:block:client:" + clientFingerprint, "1", recoveryBlockSeconds);
        }
    }

    /** Clears username/client attempt counters and block markers after all recovery codes match. */
    /** @param normalizedUsername canonical account username */
    /** @param clientFingerprint client/device fingerprint */
    public void clearFailures(String normalizedUsername, String clientFingerprint) {
        redisContract.deleteValue("auth:recovery:attempts:user:" + normalizedUsername);
        redisContract.deleteValue("auth:recovery:block:user:" + normalizedUsername);
        redisContract.deleteValue("auth:recovery:attempts:client:" + clientFingerprint);
        redisContract.deleteValue("auth:recovery:block:client:" + clientFingerprint);
    }
}
