package com.kerosene.auth.application.service.recovery.start;

import java.util.List;

import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;
import com.kerosene.auth.model.entity.UserDataBase;

/** Mutable data passed through the emergency-recovery start validation chain. */
public class EmergencyRecoveryStartContext {

    /** Original request containing replacement secrets and submitted recovery proofs. */
    private final EmergencyRecoveryStartRequest request;
    /** Client/device fingerprint used to scope abuse controls. */
    private final String clientFingerprint;
    /** Canonical account username produced by request validation. */
    private String normalizedUsername;
    /** Distinct normalized recovery codes supplied by the request. */
    private List<String> normalizedRecoveryCodes = List.of();
    /** Persisted account loaded after validation and rate-limit checks. */
    private UserDataBase user;
    /** Stored hashes corresponding to the recovery codes accepted by the final proof step. */
    private List<String> matchedRecoveryCodeHashes = List.of();

    /**
     * Initializes the shared chain state from the request and client fingerprint.
     * @param request recovery start request
     * @param clientFingerprint stable client reference
     */
    public EmergencyRecoveryStartContext(EmergencyRecoveryStartRequest request, String clientFingerprint) {
        this.request = request;
        this.clientFingerprint = clientFingerprint;
    }

    /**
     * Returns the submitted start request.
     * @return original request
     */
    public EmergencyRecoveryStartRequest request() {
        return request;
    }

    /**
     * Returns the fingerprint used for client-scoped throttling.
     * @return client fingerprint
     */
    public String clientFingerprint() {
        return clientFingerprint;
    }

    /**
     * Returns the canonicalized username.
     * @return normalized username, or null before validation
     */
    public String normalizedUsername() {
        return normalizedUsername;
    }

    /**
     * Stores the canonicalized username for subsequent handlers.
     * @param normalizedUsername canonical username
     */
    public void setNormalizedUsername(String normalizedUsername) {
        this.normalizedUsername = normalizedUsername;
    }

    /**
     * Returns the normalized distinct recovery-code candidates.
     * @return normalized submitted codes
     */
    public List<String> normalizedRecoveryCodes() {
        return normalizedRecoveryCodes;
    }

    /**
     * Stores normalized recovery-code candidates for eligibility and hash matching.
     * @param normalizedRecoveryCodes distinct normalized codes
     */
    public void setNormalizedRecoveryCodes(List<String> normalizedRecoveryCodes) {
        this.normalizedRecoveryCodes = normalizedRecoveryCodes;
    }

    /**
     * Returns the account loaded by the eligibility handler.
     * @return persisted account or null before lookup
     */
    public UserDataBase user() {
        return user;
    }

    /**
     * Stores the account resolved by the eligibility handler.
     * @param user persisted account
     */
    public void setUser(UserDataBase user) {
        this.user = user;
    }

    /**
     * Returns matched persisted recovery-code hashes after proof validation.
     * @return hashes selected for one-time use
     */
    public List<String> matchedRecoveryCodeHashes() {
        return matchedRecoveryCodeHashes;
    }

    /**
     * Stores matched hashes for the subsequent recovery-session creation step.
     * @param matchedRecoveryCodeHashes accepted stored hashes
     */
    public void setMatchedRecoveryCodeHashes(List<String> matchedRecoveryCodeHashes) {
        this.matchedRecoveryCodeHashes = matchedRecoveryCodeHashes;
    }
}
