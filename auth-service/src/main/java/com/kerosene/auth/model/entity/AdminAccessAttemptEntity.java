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
import com.kerosene.auth.model.enums.AdminAccessAttemptStatus;

/**
 * Persistence record for an administrator access request initiated from a registered device.
 * The row links one user to one device and tracks the approval lifecycle and request expiry.
 */
@Entity
@Table(schema = "auth", name = "admin_access_attempts")
public class AdminAccessAttemptEntity {

    /** Required by JPA when materializing an attempt row. */
    public AdminAccessAttemptEntity() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserDataBase user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_row_id", nullable = false)
    private AdminAccessDeviceEntity device;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private AdminAccessAttemptStatus status = AdminAccessAttemptStatus.PENDING;

    @Column(name = "browser", length = 128)
    private String browser;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "ip_fingerprint", length = 64)
    private String ipFingerprint;

    @Column(name = "requested_at", nullable = false)
    private LocalDateTime requestedAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "decided_at")
    private LocalDateTime decidedAt;

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return database identifier generated when this attempt is persisted
     */
    public UUID getId() {
        return id;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return account that requested administrator access
     */
    public UserDataBase getUser() {
        return user;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param user owning account; must be persisted before this attempt is stored
     */
    public void setUser(UserDataBase user) {
        this.user = user;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return registered device that initiated the access request
     */
    public AdminAccessDeviceEntity getDevice() {
        return device;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param device registered device associated with the access attempt
     */
    public void setDevice(AdminAccessDeviceEntity device) {
        this.device = device;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return current approval, redemption, denial, or expiry state
     */
    public AdminAccessAttemptStatus getStatus() {
        return status;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param status next lifecycle state persisted for this attempt
     */
    public void setStatus(AdminAccessAttemptStatus status) {
        this.status = status;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return browser label supplied for audit context, if available
     */
    public String getBrowser() {
        return browser;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param browser bounded browser label captured with the request
     */
    public void setBrowser(String browser) {
        this.browser = browser;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return user-agent string captured for audit context, if available
     */
    public String getUserAgent() {
        return userAgent;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param userAgent bounded user-agent value captured with the request
     */
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return one-way IP fingerprint used for request correlation, if available
     */
    public String getIpFingerprint() {
        return ipFingerprint;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param ipFingerprint privacy-preserving fingerprint; do not store the raw client address here
     */
    public void setIpFingerprint(String ipFingerprint) {
        this.ipFingerprint = ipFingerprint;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return timestamp when the request was created
     */
    public LocalDateTime getRequestedAt() {
        return requestedAt;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param requestedAt creation time used for ordering pending access attempts
     */
    public void setRequestedAt(LocalDateTime requestedAt) {
        this.requestedAt = requestedAt;
    }

    /**
     * Returns the value recorded for this access attempt.
     *
     * @return timestamp after which a pending request must no longer be approved
     */
    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    /**
     * Updates the corresponding access-attempt value.
     *
     * @param expiresAt approval deadline for this attempt
     */
    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    /**
     * Returns when an administrator decision was recorded.
     *
     * @return decision timestamp, or null while the attempt is undecided
     */
    public LocalDateTime getDecidedAt() {
        return decidedAt;
    }

    /**
     * Updates the decision timestamp.
     *
     * @param decidedAt decision timestamp; null while the attempt remains undecided
     */
    public void setDecidedAt(LocalDateTime decidedAt) {
        this.decidedAt = decidedAt;
    }
}
