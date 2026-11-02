package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

import java.util.List;

/** Request that starts emergency recovery with identity, replacement password, recovery codes, and challenge proof. */
public class EmergencyRecoveryStartRequest {

    /** Creates an empty request for Jackson to populate from the recovery-start JSON body. */
    public EmergencyRecoveryStartRequest() {
    }

    /** Account name used to locate the recovery-eligible user. */
    private String username;

    /** Replacement passphrase supplied during recovery; Jackson accepts it only on input. */
    @JsonProperty(access = Access.WRITE_ONLY)
    private char[] newPassphrase;

    /** One-time recovery codes submitted as the first recovery factor. */
    @JsonProperty(access = Access.WRITE_ONLY)
    private List<String> recoveryCodes;

    /** Proof-of-work challenge identifier/value issued by the start endpoint. */
    private String challenge;
    /** Client nonce bound to the proof-of-work solution to prevent replay. */
    private String nonce;

    /**
     * Returns account name used to locate the recovery-eligible user .
     * @return username value
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets account name used to locate the recovery-eligible user.
     * @param username username value
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns replacement passphrase supplied during recovery; Jackson accepts it only on input .
     * @return newPassphrase value
     */
    public char[] getNewPassphrase() {
        return newPassphrase;
    }

    /**
     * Sets replacement passphrase supplied during recovery; Jackson accepts it only on input.
     * @param newPassphrase newPassphrase value
     */
    public void setNewPassphrase(char[] newPassphrase) {
        this.newPassphrase = newPassphrase;
    }

    /**
     * Returns one-time recovery codes submitted as the first recovery factor .
     * @return recoveryCodes value
     */
    public List<String> getRecoveryCodes() {
        return recoveryCodes;
    }

    /**
     * Sets one-time recovery codes submitted as the first recovery factor.
     * @param recoveryCodes recoveryCodes value
     */
    public void setRecoveryCodes(List<String> recoveryCodes) {
        this.recoveryCodes = recoveryCodes;
    }

    /**
     * Returns proof-of-work challenge identifier/value issued by the start endpoint .
     * @return challenge value
     */
    public String getChallenge() {
        return challenge;
    }

    /**
     * Sets proof-of-work challenge identifier/value issued by the start endpoint.
     * @param challenge challenge value
     */
    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    /**
     * Returns client nonce bound to the proof-of-work solution to prevent replay .
     * @return nonce value
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Sets client nonce bound to the proof-of-work solution to prevent replay.
     * @param nonce nonce value
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
}
