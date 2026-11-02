package com.kerosene.auth.model.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.UUID;

/**
 * Persisted Ed25519 device credential used for challenge-response authentication.
 * The row stores the public key and monotonic replay counter, never the device private key;
 * status and revocation timestamps determine whether a credential may authenticate.
 */
@Entity
@Table(
        schema = "auth",
        name = "device_key_credentials",
        indexes = {
                @Index(name = "idx_device_key_user_id", columnList = "user_id"),
                @Index(name = "idx_device_key_install_id", columnList = "device_install_id"),
                @Index(name = "idx_device_key_status", columnList = "status")
        })
public class DeviceKeyCredential {

    /** Creates an empty credential row for JPA materialization and verified registration. */
    public DeviceKeyCredential() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserDataBase user;

    @Column(name = "credential_id", nullable = false, unique = true, length = 128)
    private String credentialId;

    @Column(name = "user_handle", nullable = false, length = 255)
    private String userHandle;

    @Column(name = "public_key_ed25519", nullable = false, length = 128)
    private String publicKeyEd25519;

    @Column(name = "algorithm", nullable = false, length = 32)
    private String algorithm = "Ed25519";

    @Column(name = "counter", nullable = false)
    private long counter;

    @Column(name = "device_name")
    private String deviceName;

    @Column(name = "device_install_id", nullable = false, length = 128)
    private String deviceInstallId;

    @Column(name = "key_storage", length = 64)
    private String keyStorage;

    @Column(name = "platform", length = 128)
    private String platform;

    @Column(name = "browser", length = 128)
    private String browser;

    @Column(name = "onion_service_id", nullable = false, length = 255)
    private String onionServiceId;

    @Column(name = "status", nullable = false, length = 32)
    private String status = "ACTIVE";

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "protocol_version", nullable = false)
    private int protocolVersion = 1;

    @Column(name = "brand")
    private String brand;

    @Column(name = "model")
    private String model;

    @Column(name = "serial_number")
    private String serialNumber;

    /**
     * Returns the database identifier generated for this credential row.
     *
     * @return database identifier generated for this credential row
     */
    public UUID getId() {
        return id;
    }

    /**
     * Updates the database identifier generated for this credential row.
     *
     * @param id database identifier generated for this credential row
     */
    public void setId(UUID id) {
        this.id = id;
    }

    /**
     * Returns the account that owns this credential.
     *
     * @return account that owns this credential
     */
    public UserDataBase getUser() {
        return user;
    }

    /**
     * Updates the account that owns this credential.
     *
     * @param user account that owns this credential
     */
    public void setUser(UserDataBase user) {
        this.user = user;
    }

    /**
     * Returns the globally unique protocol credential identifier used to locate the public key.
     *
     * @return globally unique protocol credential identifier used to locate the public key
     */
    public String getCredentialId() {
        return credentialId;
    }

    /**
     * Updates the globally unique protocol credential identifier used to locate the public key.
     *
     * @param credentialId globally unique protocol credential identifier used to locate the public key
     */
    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    /**
     * Returns the stable protocol user handle bound to the credential.
     *
     * @return stable protocol user handle bound to the credential
     */
    public String getUserHandle() {
        return userHandle;
    }

    /**
     * Updates the stable protocol user handle bound to the credential.
     *
     * @param userHandle stable protocol user handle bound to the credential
     */
    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }

    /**
     * Returns the encoded Ed25519 public key used to verify signatures; private key material is not stored here.
     *
     * @return encoded Ed25519 public key used to verify signatures; private key material is not stored here
     */
    public String getPublicKeyEd25519() {
        return publicKeyEd25519;
    }

    /**
     * Updates the encoded Ed25519 public key used to verify signatures; private key material is not stored here.
     *
     * @param publicKeyEd25519 encoded Ed25519 public key used to verify signatures; private key material is not stored here
     */
    public void setPublicKeyEd25519(String publicKeyEd25519) {
        this.publicKeyEd25519 = publicKeyEd25519;
    }

    /**
     * Returns the signature algorithm associated with the credential, defaulting to Ed25519.
     *
     * @return signature algorithm associated with the credential, defaulting to Ed25519
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Updates the signature algorithm associated with the credential, defaulting to Ed25519.
     *
     * @param algorithm signature algorithm associated with the credential, defaulting to Ed25519
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Returns the last accepted monotonic authenticator counter used to reject replayed assertions.
     *
     * @return last accepted monotonic authenticator counter used to reject replayed assertions
     */
    public long getCounter() {
        return counter;
    }

    /**
     * Updates the last accepted monotonic authenticator counter used to reject replayed assertions.
     *
     * @param counter last accepted monotonic authenticator counter used to reject replayed assertions
     */
    public void setCounter(long counter) {
        this.counter = counter;
    }

    /**
     * Returns the human-readable label supplied for the registered device.
     *
     * @return human-readable label supplied for the registered device
     */
    public String getDeviceName() {
        return deviceName;
    }

    /**
     * Updates the human-readable label supplied for the registered device.
     *
     * @param deviceName human-readable label supplied for the registered device
     */
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    /**
     * Returns the stable installation identifier used by account-binding policy.
     *
     * @return stable installation identifier used by account-binding policy
     */
    public String getDeviceInstallId() {
        return deviceInstallId;
    }

    /**
     * Updates the stable installation identifier used by account-binding policy.
     *
     * @param deviceInstallId stable installation identifier used by account-binding policy
     */
    public void setDeviceInstallId(String deviceInstallId) {
        this.deviceInstallId = deviceInstallId;
    }

    /**
     * Returns the client-reported storage class for the private key.
     *
     * @return client-reported storage class for the private key
     */
    public String getKeyStorage() {
        return keyStorage;
    }

    /**
     * Updates the client-reported storage class for the private key.
     *
     * @param keyStorage client-reported storage class for the private key
     */
    public void setKeyStorage(String keyStorage) {
        this.keyStorage = keyStorage;
    }

    /**
     * Returns the operating-system or platform family reported at registration.
     *
     * @return operating-system or platform family reported at registration
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Updates the operating-system or platform family reported at registration.
     *
     * @param platform operating-system or platform family reported at registration
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Returns the browser family reported at registration.
     *
     * @return browser family reported at registration
     */
    public String getBrowser() {
        return browser;
    }

    /**
     * Updates the browser family reported at registration.
     *
     * @param browser browser family reported at registration
     */
    public void setBrowser(String browser) {
        this.browser = browser;
    }

    /**
     * Returns the onion service identity associated with the registered client.
     *
     * @return onion service identity associated with the registered client
     */
    public String getOnionServiceId() {
        return onionServiceId;
    }

    /**
     * Updates the onion service identity associated with the registered client.
     *
     * @param onionServiceId onion service identity associated with the registered client
     */
    public void setOnionServiceId(String onionServiceId) {
        this.onionServiceId = onionServiceId;
    }

    /**
     * Returns the normalized credential lifecycle state such as ACTIVE or REVOKED.
     *
     * @return normalized credential lifecycle state such as ACTIVE or REVOKED
     */
    public String getStatus() {
        return status;
    }

    /**
     * Updates the normalized credential lifecycle state such as ACTIVE or REVOKED.
     * Blank or null status is normalized to ACTIVE; other values are trimmed and uppercased.
     *
     * @param status normalized credential lifecycle state such as ACTIVE or REVOKED
     */
    public void setStatus(String status) {
        this.status = status == null || status.isBlank()
                ? "ACTIVE"
                : status.trim().toUpperCase(Locale.ROOT);
    }

    /**
     * Returns the database-generated enrollment timestamp.
     *
     * @return database-generated enrollment timestamp
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Returns the timestamp of the last accepted authentication assertion.
     *
     * @return timestamp of the last accepted authentication assertion
     */
    public LocalDateTime getLastUsedAt() {
        return lastUsedAt;
    }

    /**
     * Updates the timestamp of the last accepted authentication assertion.
     *
     * @param lastUsedAt timestamp of the last accepted authentication assertion
     */
    public void setLastUsedAt(LocalDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    /**
     * Returns the timestamp when this credential was revoked, or null while active.
     *
     * @return timestamp when this credential was revoked, or null while active
     */
    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    /**
     * Updates the timestamp when this credential was revoked, or null while active.
     *
     * @param revokedAt timestamp when this credential was revoked, or null while active
     */
    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    /**
     * Returns the device-key protocol version used when the credential was registered.
     *
     * @return device-key protocol version used when the credential was registered
     */
    public int getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Updates the device-key protocol version used when the credential was registered.
     *
     * @param protocolVersion device-key protocol version used when the credential was registered
     */
    public void setProtocolVersion(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    /**
     * Returns the optional device manufacturer label.
     *
     * @return optional device manufacturer label
     */
    public String getBrand() {
        return brand;
    }

    /**
     * Updates the optional device manufacturer label.
     *
     * @param brand optional device manufacturer label
     */
    public void setBrand(String brand) {
        this.brand = brand;
    }

    /**
     * Returns the optional device model label.
     *
     * @return optional device model label
     */
    public String getModel() {
        return model;
    }

    /**
     * Updates the optional device model label.
     *
     * @param model optional device model label
     */
    public void setModel(String model) {
        this.model = model;
    }

    /**
     * Returns the optional device serial reference; treat as sensitive identifying metadata.
     *
     * @return optional device serial reference; treat as sensitive identifying metadata
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Updates the optional device serial reference; treat as sensitive identifying metadata.
     *
     * @param serialNumber optional device serial reference; treat as sensitive identifying metadata
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }
}
