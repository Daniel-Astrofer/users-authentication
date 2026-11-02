package com.kerosene.auth.dto.devicekey;

/** Request carrying a device public key, signed enrollment proof, and device metadata. */
public class DeviceKeyRegistrationRequest {
    /** Creates an empty request for Jackson to populate from the registration JSON body. */
    public DeviceKeyRegistrationRequest() {
    }

    /** Encoded public key registered for later signature verification. */
    private String publicKey;
    /** Claimed SHA-256 fingerprint checked against the decoded public key. */
    private String publicKeySha256;
    /** Client-selected credential identifier bound into the signed enrollment. */
    private String credentialId;
    /** Opaque client handle included when the protocol provides one. */
    private String userHandle;
    /** Human-readable label displayed in the account device list. */
    private String deviceName;
    /** Stable installation identity used for device-scoped credential management. */
    private String deviceInstallId;
    /** Client declaration of hardware or software private-key storage. */
    private String keyStorage;
    /** Operating system or client platform identifier. */
    private String platform;
    /** Browser identifier when the request comes from a browser. */
    private String browser;
    /** Optional hardware manufacturer metadata. */
    private String brand;
    /** Optional hardware model metadata. */
    private String model;
    /** Optional serial metadata; avoid sending it unless policy requires it. */
    private String serialNumber;
    /** Canonical registration payload covered by the detached signature. */
    private String signedPayload;
    /** Proof-of-possession signature corresponding to the submitted public key. */
    private String signature;
    /** Explicit consent to delete previous account credentials for this installation. */
    private boolean confirmUnlinkDevice;

    /**
     * Returns encoded public key registered for later signature verification.
     * @return public key material
     */
    public String getPublicKey() { return publicKey; }
    /**
     * Sets encoded public key registered for later signature verification.
     * @param publicKey public key material
     */
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    /**
     * Returns claimed SHA-256 fingerprint checked against the decoded public key.
     * @return SHA-256 fingerprint
     */
    public String getPublicKeySha256() { return publicKeySha256; }
    /**
     * Sets claimed SHA-256 fingerprint checked against the decoded public key.
     * @param publicKeySha256 SHA-256 fingerprint
     */
    public void setPublicKeySha256(String publicKeySha256) { this.publicKeySha256 = publicKeySha256; }
    /**
     * Returns client-selected credential identifier bound into the signed enrollment.
     * @return credential identifier
     */
    public String getCredentialId() { return credentialId; }
    /**
     * Sets client-selected credential identifier bound into the signed enrollment.
     * @param credentialId credential identifier
     */
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
    /**
     * Returns opaque client handle included when the protocol provides one.
     * @return opaque user handle
     */
    public String getUserHandle() { return userHandle; }
    /**
     * Sets opaque client handle included when the protocol provides one.
     * @param userHandle opaque user handle
     */
    public void setUserHandle(String userHandle) { this.userHandle = userHandle; }
    /**
     * Returns human-readable label displayed in the account device list.
     * @return device display name
     */
    public String getDeviceName() { return deviceName; }
    /**
     * Sets human-readable label displayed in the account device list.
     * @param deviceName device display name
     */
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }
    /**
     * Returns stable installation identity used for device-scoped credential management.
     * @return installation identifier
     */
    public String getDeviceInstallId() { return deviceInstallId; }
    /**
     * Sets stable installation identity used for device-scoped credential management.
     * @param deviceInstallId installation identifier
     */
    public void setDeviceInstallId(String deviceInstallId) { this.deviceInstallId = deviceInstallId; }
    /**
     * Returns client declaration of hardware or software private-key storage.
     * @return storage descriptor
     */
    public String getKeyStorage() { return keyStorage; }
    /**
     * Sets client declaration of hardware or software private-key storage.
     * @param keyStorage storage descriptor
     */
    public void setKeyStorage(String keyStorage) { this.keyStorage = keyStorage; }
    /**
     * Returns operating system or client platform identifier.
     * @return platform identifier
     */
    public String getPlatform() { return platform; }
    /**
     * Sets operating system or client platform identifier.
     * @param platform platform identifier
     */
    public void setPlatform(String platform) { this.platform = platform; }
    /**
     * Returns browser identifier when the request comes from a browser.
     * @return browser identifier
     */
    public String getBrowser() { return browser; }
    /**
     * Sets browser identifier when the request comes from a browser.
     * @param browser browser identifier
     */
    public void setBrowser(String browser) { this.browser = browser; }
    /**
     * Returns optional hardware manufacturer metadata.
     * @return device brand
     */
    public String getBrand() { return brand; }
    /**
     * Sets optional hardware manufacturer metadata.
     * @param brand device brand
     */
    public void setBrand(String brand) { this.brand = brand; }
    /**
     * Returns optional hardware model metadata.
     * @return device model
     */
    public String getModel() { return model; }
    /**
     * Sets optional hardware model metadata.
     * @param model device model
     */
    public void setModel(String model) { this.model = model; }
    /**
     * Returns optional serial metadata; avoid sending it unless policy requires it.
     * @return device serial number
     */
    public String getSerialNumber() { return serialNumber; }
    /**
     * Sets optional serial metadata; avoid sending it unless policy requires it.
     * @param serialNumber device serial number
     */
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }
    /**
     * Returns canonical registration payload covered by the detached signature.
     * @return exact signed payload
     */
    public String getSignedPayload() { return signedPayload; }
    /**
     * Sets canonical registration payload covered by the detached signature.
     * @param signedPayload exact signed payload
     */
    public void setSignedPayload(String signedPayload) { this.signedPayload = signedPayload; }
    /**
     * Returns proof-of-possession signature corresponding to the submitted public key.
     * @return encoded signature
     */
    public String getSignature() { return signature; }
    /**
     * Sets proof-of-possession signature corresponding to the submitted public key.
     * @param signature encoded signature
     */
    public void setSignature(String signature) { this.signature = signature; }
    /**
     * Returns explicit consent to delete previous account credentials for this installation.
     * @return unlink confirmation
     */
    public boolean isConfirmUnlinkDevice() { return confirmUnlinkDevice; }
    /**
     * Sets explicit consent to delete previous account credentials for this installation.
     * @param confirmUnlinkDevice unlink confirmation
     */
    public void setConfirmUnlinkDevice(boolean confirmUnlinkDevice) { this.confirmUnlinkDevice = confirmUnlinkDevice; }
}
