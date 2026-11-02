package com.kerosene.auth.dto;

/** Response for a started recovery session; exposes the next TOTP/passkey proofs and expiry. */
public class EmergencyRecoveryStartResponse {

    /** Opaque, short-lived identifier required to finish this recovery attempt. */
    private String recoverySessionId;
    /** Provisioning URI for the TOTP secret associated with recovery. */
    private String otpUri;
    /** Challenge to sign with an eligible passkey during recovery. */
    private String passkeyChallenge;
    /** Remaining lifetime of the recovery session. */
    private long expiresInSeconds;
    /** Number of distinct unused recovery codes required by policy. */
    private int requiredRecoveryCodes;

    /** True when fresh canonical enrollment challenges can be obtained after authenticator setup. */
    private boolean deviceKeyRecoverySupported;

    public boolean isDeviceKeyRecoverySupported() { return deviceKeyRecoverySupported; }

    public void setDeviceKeyRecoverySupported(boolean deviceKeyRecoverySupported) {
        this.deviceKeyRecoverySupported = deviceKeyRecoverySupported;
    }

    /** Creates an empty response for serializer-based construction. */
    public EmergencyRecoveryStartResponse() {
    }

    /** Creates the complete start response returned to the recovery client.
     * @param recoverySessionId short-lived session identifier
     * @param otpUri TOTP provisioning URI
     * @param passkeyChallenge challenge to sign
     * @param expiresInSeconds session lifetime in seconds
     * @param requiredRecoveryCodes number of codes required to proceed
     */
    public EmergencyRecoveryStartResponse(String recoverySessionId, String otpUri, String passkeyChallenge,
            long expiresInSeconds, int requiredRecoveryCodes) {
        this.recoverySessionId = recoverySessionId;
        this.otpUri = otpUri;
        this.passkeyChallenge = passkeyChallenge;
        this.expiresInSeconds = expiresInSeconds;
        this.requiredRecoveryCodes = requiredRecoveryCodes;
    }

    /**
     * Returns opaque, short-lived identifier required to finish this recovery attempt..
     * @return recoverySessionId value
     */
    public String getRecoverySessionId() {
        return recoverySessionId;
    }

    /**
     * Sets opaque, short-lived identifier required to finish this recovery attempt.
     * @param recoverySessionId recoverySessionId value
     */
    public void setRecoverySessionId(String recoverySessionId) {
        this.recoverySessionId = recoverySessionId;
    }

    /**
     * Returns provisioning URI for the TOTP secret associated with recovery..
     * @return otpUri value
     */
    public String getOtpUri() {
        return otpUri;
    }

    /**
     * Sets provisioning URI for the TOTP secret associated with recovery.
     * @param otpUri otpUri value
     */
    public void setOtpUri(String otpUri) {
        this.otpUri = otpUri;
    }

    /**
     * Returns challenge to sign with an eligible passkey during recovery..
     * @return passkeyChallenge value
     */
    public String getPasskeyChallenge() {
        return passkeyChallenge;
    }

    /**
     * Sets challenge to sign with an eligible passkey during recovery.
     * @param passkeyChallenge passkeyChallenge value
     */
    public void setPasskeyChallenge(String passkeyChallenge) {
        this.passkeyChallenge = passkeyChallenge;
    }

    /**
     * Returns remaining lifetime of the recovery session..
     * @return expiresInSeconds value
     */
    public long getExpiresInSeconds() {
        return expiresInSeconds;
    }

    /**
     * Sets remaining lifetime of the recovery session.
     * @param expiresInSeconds expiresInSeconds value
     */
    public void setExpiresInSeconds(long expiresInSeconds) {
        this.expiresInSeconds = expiresInSeconds;
    }

    /**
     * Returns number of distinct unused recovery codes required by policy..
     * @return requiredRecoveryCodes value
     */
    public int getRequiredRecoveryCodes() {
        return requiredRecoveryCodes;
    }

    /**
     * Sets number of distinct unused recovery codes required by policy.
     * @param requiredRecoveryCodes requiredRecoveryCodes value
     */
    public void setRequiredRecoveryCodes(int requiredRecoveryCodes) {
        this.requiredRecoveryCodes = requiredRecoveryCodes;
    }
}
