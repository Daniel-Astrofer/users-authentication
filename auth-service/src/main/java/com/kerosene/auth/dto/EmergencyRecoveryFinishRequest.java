package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

/** Request that finishes recovery by presenting the session's TOTP and passkey proofs plus device metadata. */
public class EmergencyRecoveryFinishRequest {

    /** Creates an empty request for Jackson to populate from the recovery-finish JSON body. */
    public EmergencyRecoveryFinishRequest() {
    }

    /** Opaque identifier for the short-lived recovery state created by the start request. */
    private String recoverySessionId;

    /** Write-only authenticator code used as a recovery factor. */
    @JsonProperty(access = Access.WRITE_ONLY)
    private String totpCode;

    /** Encoded public key to register for subsequent passkey authentication. */
    private String publicKey;
    /** COSE-encoded public key representation used by the passkey protocol. */
    private String publicKeyCose;
    /** Human-readable label for the newly registered recovery device. */
    private String deviceName;
    /** Detached signature proving possession of the passkey private key. */
    private String signature;
    /** Authenticator data returned by the WebAuthn-style credential response. */
    private String authData;
    /** Client data JSON returned by the WebAuthn-style credential response. */
    private String clientDataJSON;
    /** Credential identifier associated with the submitted public key. */
    private String credentialId;
    /** Opaque user handle bound to the passkey credential. */
    private String userHandle;
    /** Stable device installation identity used for credential uniqueness checks. */
    private String deviceInstallId;
    /** Optional device manufacturer metadata. */
    private String brand;
    /** Optional device model metadata. */
    private String model;
    /** Optional serial metadata that may identify the physical device. */
    private String serialNumber;
    /** Operating system or platform reported by the recovery client. */
    private String platform;
    /** Browser identifier when recovery is performed in a browser. */
    private String browser;
    /** Compatibility field. Recovery of one account does not authorize deletion of another account's credentials. */
    private boolean confirmUnlinkDevice;

    /** Canonical device-key registration proof, mutually exclusive with legacy passkey proof. */
    private com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest deviceKeyRegistration;

    public com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest getDeviceKeyRegistration() {
        return deviceKeyRegistration;
    }

    public void setDeviceKeyRegistration(com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest deviceKeyRegistration) {
        this.deviceKeyRegistration = deviceKeyRegistration;
    }

    /**
     * Returns opaque identifier for the short-lived recovery state created by the start request..
     * @return recoverySessionId value
     */
    public String getRecoverySessionId() {
        return recoverySessionId;
    }

    /**
     * Sets opaque identifier for the short-lived recovery state created by the start request.
     * @param recoverySessionId recoverySessionId value
     */
    public void setRecoverySessionId(String recoverySessionId) {
        this.recoverySessionId = recoverySessionId;
    }

    /**
     * Returns write-only authenticator code used as a recovery factor..
     * @return totpCode value
     */
    public String getTotpCode() {
        return totpCode;
    }

    /**
     * Sets write-only authenticator code used as a recovery factor.
     * @param totpCode totpCode value
     */
    public void setTotpCode(String totpCode) {
        this.totpCode = totpCode;
    }

    /**
     * Returns encoded public key to register for subsequent passkey authentication..
     * @return publicKey value
     */
    public String getPublicKey() {
        return publicKey;
    }

    /**
     * Sets encoded public key to register for subsequent passkey authentication.
     * @param publicKey publicKey value
     */
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Returns cOSE-encoded public key representation used by the passkey protocol..
     * @return publicKeyCose value
     */
    public String getPublicKeyCose() {
        return publicKeyCose;
    }

    /**
     * Sets cOSE-encoded public key representation used by the passkey protocol.
     * @param publicKeyCose publicKeyCose value
     */
    public void setPublicKeyCose(String publicKeyCose) {
        this.publicKeyCose = publicKeyCose;
    }

    /**
     * Returns human-readable label for the newly registered recovery device..
     * @return deviceName value
     */
    public String getDeviceName() {
        return deviceName;
    }

    /**
     * Sets human-readable label for the newly registered recovery device.
     * @param deviceName deviceName value
     */
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    /**
     * Returns detached signature proving possession of the passkey private key..
     * @return signature value
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Sets detached signature proving possession of the passkey private key.
     * @param signature signature value
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Returns authenticator data returned by the WebAuthn-style credential response..
     * @return authData value
     */
    public String getAuthData() {
        return authData;
    }

    /**
     * Sets authenticator data returned by the WebAuthn-style credential response.
     * @param authData authData value
     */
    public void setAuthData(String authData) {
        this.authData = authData;
    }

    /**
     * Returns client data JSON returned by the WebAuthn-style credential response..
     * @return clientDataJSON value
     */
    public String getClientDataJSON() {
        return clientDataJSON;
    }

    /**
     * Sets client data JSON returned by the WebAuthn-style credential response.
     * @param clientDataJSON clientDataJSON value
     */
    public void setClientDataJSON(String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    /**
     * Returns credential identifier associated with the submitted public key..
     * @return credentialId value
     */
    public String getCredentialId() {
        return credentialId;
    }

    /**
     * Sets credential identifier associated with the submitted public key.
     * @param credentialId credentialId value
     */
    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    /**
     * Returns opaque user handle bound to the passkey credential..
     * @return userHandle value
     */
    public String getUserHandle() {
        return userHandle;
    }

    /**
     * Sets opaque user handle bound to the passkey credential.
     * @param userHandle userHandle value
     */
    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }

    /**
     * Returns stable device installation identity used for credential uniqueness checks..
     * @return deviceInstallId value
     */
    public String getDeviceInstallId() {
        return deviceInstallId;
    }

    /**
     * Sets stable device installation identity used for credential uniqueness checks.
     * @param deviceInstallId deviceInstallId value
     */
    public void setDeviceInstallId(String deviceInstallId) {
        this.deviceInstallId = deviceInstallId;
    }

    /**
     * Returns optional device manufacturer metadata..
     * @return brand value
     */
    public String getBrand() {
        return brand;
    }

    /**
     * Sets optional device manufacturer metadata.
     * @param brand brand value
     */
    public void setBrand(String brand) {
        this.brand = brand;
    }

    /**
     * Returns optional device model metadata..
     * @return model value
     */
    public String getModel() {
        return model;
    }

    /**
     * Sets optional device model metadata.
     * @param model model value
     */
    public void setModel(String model) {
        this.model = model;
    }

    /**
     * Returns optional serial metadata that may identify the physical device..
     * @return serialNumber value
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets optional serial metadata that may identify the physical device.
     * @param serialNumber serialNumber value
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * Returns operating system or platform reported by the recovery client..
     * @return platform value
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Sets operating system or platform reported by the recovery client.
     * @param platform platform value
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Returns browser identifier when recovery is performed in a browser..
     * @return browser value
     */
    public String getBrowser() {
        return browser;
    }

    /**
     * Sets browser identifier when recovery is performed in a browser.
     * @param browser browser value
     */
    public void setBrowser(String browser) {
        this.browser = browser;
    }

    /**
     * Returns compatibility flag; emergency recovery never deletes foreign account credentials..
     * @return confirmUnlinkDevice value
     */
    public boolean isConfirmUnlinkDevice() {
        return confirmUnlinkDevice;
    }

    /**
     * Sets compatibility flag; emergency recovery never deletes foreign account credentials.
     * @param confirmUnlinkDevice confirmUnlinkDevice value
     */
    public void setConfirmUnlinkDevice(boolean confirmUnlinkDevice) {
        this.confirmUnlinkDevice = confirmUnlinkDevice;
    }
}
