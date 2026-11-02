package com.kerosene.auth.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import com.kerosene.auth.model.enums.AdminKeyStatus;

/**
 * Persisted administrator key enrollment containing a non-reversible material hash and display fingerprint.
 * The original key material must never be stored in this entity; revocation and rotation are timestamped.
 */
@Entity
@Table(schema = "auth", name = "admin_keys")
public class AdminKeyEntity {

    /** Creates an empty key record for JPA materialization and enrollment setup. */
    public AdminKeyEntity() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserDataBase user;

    @Column(name = "key_material_hash", nullable = false, length = 128)
    private String keyMaterialHash;

    @Column(name = "key_fingerprint", nullable = false, length = 64)
    private String keyFingerprint;

    @Column(name = "device_install_id", length = 128)
    private String deviceInstallId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private AdminKeyStatus status = AdminKeyStatus.ACTIVE;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "rotated_at")
    private LocalDateTime rotatedAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    /**
     * Returns the database identifier generated for the key record.
     *
     * @return database identifier generated for the key record
     */
    public UUID getId() {
        return id;
    }

    /**
     * Returns the persisted account that owns the key enrollment.
     *
     * @return account that owns the key enrollment
     */
    public UserDataBase getUser() {
        return user;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param user owning account for this enrollment
     */
    public void setUser(UserDataBase user) {
        this.user = user;
    }

    /**
     * Returns the persisted normalized non-reversible key verifier; never expose it in an API response.
     *
     * @return normalized non-reversible key verifier; never expose it in an API response
     */
    public String getKeyMaterialHash() {
        return keyMaterialHash;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param keyMaterialHash normalized non-reversible verifier; raw key material must not be passed
     */
    public void setKeyMaterialHash(String keyMaterialHash) {
        this.keyMaterialHash = keyMaterialHash;
    }

    /**
     * Returns the persisted non-secret fingerprint safe to show when identifying the configured key.
     *
     * @return non-secret fingerprint safe to show when identifying the configured key
     */
    public String getKeyFingerprint() {
        return keyFingerprint;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param keyFingerprint non-secret display fingerprint derived from the verifier
     */
    public void setKeyFingerprint(String keyFingerprint) {
        this.keyFingerprint = keyFingerprint;
    }

    /**
     * Returns the persisted installation identifier to which the key enrollment is bound, when supplied.
     *
     * @return installation identifier to which the key enrollment is bound, when supplied
     */
    public String getDeviceInstallId() {
        return deviceInstallId;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param deviceInstallId stable installation identifier bound to the enrollment
     */
    public void setDeviceInstallId(String deviceInstallId) {
        this.deviceInstallId = deviceInstallId;
    }

    /**
     * Returns the persisted current active or revoked lifecycle state.
     *
     * @return current active or revoked lifecycle state
     */
    public AdminKeyStatus getStatus() {
        return status;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param status new lifecycle state
     */
    public void setStatus(AdminKeyStatus status) {
        this.status = status;
    }

    /**
     * Returns the persisted database-generated enrollment time.
     *
     * @return database-generated enrollment time
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Returns the persisted time this key was replaced by a newer enrollment, or null when never rotated.
     *
     * @return time this key was replaced by a newer enrollment, or null when never rotated
     */
    public LocalDateTime getRotatedAt() {
        return rotatedAt;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param rotatedAt replacement time, or null when no rotation has occurred
     */
    public void setRotatedAt(LocalDateTime rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    /**
     * Returns the persisted time the key was invalidated, or null while not revoked.
     *
     * @return time the key was invalidated, or null while not revoked
     */
    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    /**
     * Updates the persisted key enrollment field.
     *
     * @param revokedAt invalidation time, or null while the key remains active
     */
    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }
}
