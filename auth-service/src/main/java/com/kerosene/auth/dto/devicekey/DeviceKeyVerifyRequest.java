package com.kerosene.auth.dto.devicekey;

/** Login-time request proving possession of a registered device private key. */
public class DeviceKeyVerifyRequest {
    /** Creates an empty request for Jackson to populate from the authentication JSON body. */
    public DeviceKeyVerifyRequest() {
    }

    /** Username that selects the account whose credential must be checked. */
    private String username;
    /**
     * Returns the account username.
     * @return account username
     */
    public String getUsername() { return username; }
    /**
     * Sets the account username used by challenge verification.
     * @param username account username
     */
    public void setUsername(String username) { this.username = username; }
    /** Registered device credential selected for proof of possession. */
    private String credentialId;
    /**
     * Returns the credential identifier.
     * @return credential identifier
     */
    public String getCredentialId() { return credentialId; }
    /**
     * Sets the credential identifier used by challenge verification.
     * @param credentialId credential identifier
     */
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
    /** Stable client installation identity included in anti-replay policy checks. */
    private String deviceInstallId;
    /**
     * Returns the installation identifier.
     * @return installation identifier
     */
    public String getDeviceInstallId() { return deviceInstallId; }
    /**
     * Sets the installation identifier used by challenge verification.
     * @param deviceInstallId installation identifier
     */
    public void setDeviceInstallId(String deviceInstallId) { this.deviceInstallId = deviceInstallId; }
    /** Canonical challenge response that the private key signed. */
    private String signedPayload;
    /**
     * Returns the exact signed payload.
     * @return exact signed payload
     */
    public String getSignedPayload() { return signedPayload; }
    /**
     * Sets the exact signed payload used by challenge verification.
     * @param signedPayload exact signed payload
     */
    public void setSignedPayload(String signedPayload) { this.signedPayload = signedPayload; }
    /** Signature over the canonical challenge response. */
    private String signature;
    /**
     * Returns the encoded signature.
     * @return encoded signature
     */
    public String getSignature() { return signature; }
    /**
     * Sets the encoded signature used by challenge verification.
     * @param signature encoded signature
     */
    public void setSignature(String signature) { this.signature = signature; }
}
