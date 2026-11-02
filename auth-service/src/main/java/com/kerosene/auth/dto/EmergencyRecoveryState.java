package com.kerosene.auth.dto;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** Serializable server-side snapshot for one short-lived recovery attempt stored in the session backend. */
public class EmergencyRecoveryState implements Serializable {
    /** Serialization compatibility identifier for persisted recovery session snapshots. */
    @Serial
    private static final long serialVersionUID = 1L;

    /** Opaque identifier used as the lookup key for this recovery attempt. */
    private String sessionId;
    /** Account name whose credentials are being recovered. */
    private String username;
    /** One-way hash of the proposed replacement passphrase; the raw passphrase is not retained here. */
    private String hashedPassphrase;
    /** Ciphertext for the replacement TOTP secret held until the recovery transaction completes. */
    private String encryptedTotpSecret;
    /** One-time passkey challenge bound to this recovery attempt. */
    private String passkeyChallenge;
    /** Hashes of distinct backup codes already matched, used to prevent duplicate code reuse. */
    private List<String> matchedBackupCodeHashes = new ArrayList<>();

    /** Creates an empty session snapshot for the configured serializer. */
    public EmergencyRecoveryState() {
    }

    /**
     * Returns opaque identifier used as the lookup key for this recovery attempt..
     * @return sessionId value
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Sets opaque identifier used as the lookup key for this recovery attempt.
     * @param sessionId sessionId value
     */
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Returns account name whose credentials are being recovered..
     * @return username value
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets account name whose credentials are being recovered.
     * @param username username value
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns one-way hash of the proposed replacement passphrase; the raw passphrase is not retained here..
     * @return hashedPassphrase value
     */
    public String getHashedPassphrase() {
        return hashedPassphrase;
    }

    /**
     * Sets one-way hash of the proposed replacement passphrase; the raw passphrase is not retained here.
     * @param hashedPassphrase hashedPassphrase value
     */
    public void setHashedPassphrase(String hashedPassphrase) {
        this.hashedPassphrase = hashedPassphrase;
    }

    /**
     * Returns ciphertext for the replacement TOTP secret held until the recovery transaction completes..
     * @return encryptedTotpSecret value
     */
    public String getEncryptedTotpSecret() {
        return encryptedTotpSecret;
    }

    /**
     * Sets ciphertext for the replacement TOTP secret held until the recovery transaction completes.
     * @param encryptedTotpSecret encryptedTotpSecret value
     */
    public void setEncryptedTotpSecret(String encryptedTotpSecret) {
        this.encryptedTotpSecret = encryptedTotpSecret;
    }

    /**
     * Returns one-time passkey challenge bound to this recovery attempt..
     * @return passkeyChallenge value
     */
    public String getPasskeyChallenge() {
        return passkeyChallenge;
    }

    /**
     * Sets one-time passkey challenge bound to this recovery attempt.
     * @param passkeyChallenge passkeyChallenge value
     */
    public void setPasskeyChallenge(String passkeyChallenge) {
        this.passkeyChallenge = passkeyChallenge;
    }

    /**
     * Returns hashes of distinct backup codes already matched, used to prevent duplicate code reuse..
     * @return matchedBackupCodeHashes value
     */
    public List<String> getMatchedBackupCodeHashes() {
        return matchedBackupCodeHashes;
    }

    /**
     * Sets hashes of distinct backup codes already matched, used to prevent duplicate code reuse.
     * @param matchedBackupCodeHashes matchedBackupCodeHashes value
     */
    public void setMatchedBackupCodeHashes(List<String> matchedBackupCodeHashes) {
        this.matchedBackupCodeHashes = matchedBackupCodeHashes;
    }
}
