package com.kerosene.auth.application.service.recovery;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.redis.contracts.RedisContract;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.dto.EmergencyRecoveryState;

/** Persists short-lived recovery sessions and consumes them atomically on completion. */
@Service
public class RecoveryStateStore {

    /** Redis state boundary, including the atomic GETDEL operation. */
    private final RedisContract redisContract;
    /** Cryptographically secure source for recovery challenges. */
    private final SecureRandom secureRandom = new SecureRandom();
    /** Hex codec for server-generated challenge bytes. */
    private static final HexFormat HEX = HexFormat.of();

    /** Configured recovery session lifetime in minutes. */
    @Value("${auth.recovery.session-ttl-minutes:10}")
    private long recoverySessionTtlMinutes;

    /** Creates the recovery session store. */
    /** @param redisContract Redis structured-state operations */
    public RecoveryStateStore(RedisContract redisContract) {
        this.redisContract = redisContract;
    }

    /** Creates random session/challenge identifiers and stores protected replacement state with a TTL. */
    /** @param context validated start context with owner and matched code hashes */
    /** @param hashedPassphrase proposed passphrase hash */
    /** @param encryptedTotpSecret protected replacement TOTP secret */
    /** @return session identifier, passkey challenge, and expiry duration */
    public StoredRecoverySession createSession(EmergencyRecoveryStartContext context, String hashedPassphrase,
            String encryptedTotpSecret) {
        String recoverySessionId = UUID.randomUUID().toString().replace("-", "");
        String passkeyChallenge = generateRecoveryChallenge();

        EmergencyRecoveryState state = new EmergencyRecoveryState();
        state.setSessionId(recoverySessionId);
        state.setUsername(context.normalizedUsername());
        state.setHashedPassphrase(hashedPassphrase);
        state.setEncryptedTotpSecret(encryptedTotpSecret);
        state.setPasskeyChallenge(passkeyChallenge);
        state.setMatchedBackupCodeHashes(context.matchedRecoveryCodeHashes());

        redisContract.saveEmergencyRecoveryState(recoverySessionId, state, recoverySessionTtlMinutes);
        return new StoredRecoverySession(recoverySessionId, passkeyChallenge, recoverySessionTtlMinutes * 60L);
    }

    /** Atomically consumes a recovery session and rejects missing, expired, or reused session IDs. */
    /** @param recoverySessionId one-time session identifier */
    /** @return consumed recovery state */
    /** @throws AuthExceptions.RecoverySessionExpiredException when session is absent or already consumed */
    public EmergencyRecoveryState consumeRequired(String recoverySessionId) {
        EmergencyRecoveryState state = redisContract.getdelEmergencyRecoveryState(recoverySessionId);
        return requireMatchingState(recoverySessionId, state);
    }

    /** Reads an existing session to prepare a short-lived key challenge without consuming completion authority. */
    public EmergencyRecoveryState readRequired(String recoverySessionId) {
        return requireMatchingState(recoverySessionId, redisContract.findEmergencyRecoveryState(recoverySessionId));
    }

    private EmergencyRecoveryState requireMatchingState(String recoverySessionId, EmergencyRecoveryState state) {
        if (recoverySessionId == null || recoverySessionId.isBlank() || state == null
                || !recoverySessionId.equals(state.getSessionId())) {
            throw new AuthExceptions.RecoverySessionExpiredException(
                    "Recovery session expired or was already consumed. Restart the recovery flow.");
        }
        return state;
    }

    /** Generates a cryptographically random 32-byte challenge in hexadecimal form. */
    /** @return lowercase hexadecimal challenge */
    private String generateRecoveryChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return HEX.formatHex(challenge);
    }

    /**
     * Public recovery session metadata returned to the client.
     * @param sessionId one-time session identifier
     * @param passkeyChallenge challenge required for replacement passkey proof
     * @param expiresInSeconds session lifetime exposed in seconds
     */
    public record StoredRecoverySession(String sessionId, String passkeyChallenge, long expiresInSeconds) {
    }
}
