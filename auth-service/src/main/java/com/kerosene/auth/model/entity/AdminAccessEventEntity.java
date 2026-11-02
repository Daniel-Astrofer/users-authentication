package com.kerosene.auth.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import com.kerosene.auth.model.enums.AdminAccessEventStatus;

/**
 * Audit record for an administrator access decision, retaining sanitized client context and outcome.
 * Fingerprint and user-agent fields are intentionally bounded and should not contain raw secrets.
 */
@Entity
@Table(schema = "auth", name = "admin_access_events")
public class AdminAccessEventEntity {

    /** Creates an empty audit entity for JPA materialization and event assembly. */
    public AdminAccessEventEntity() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "admin_id")
    private Long adminId;

    @Column(name = "device_id", length = 128)
    private String deviceId;

    @Column(name = "browser", length = 128)
    private String browser;

    @Column(name = "sanitized_user_agent", length = 512)
    private String sanitizedUserAgent;

    @Column(name = "ip_fingerprint", length = 64)
    private String ipFingerprint;

    @CreationTimestamp
    @Column(name = "occurred_at", nullable = false, updatable = false)
    private LocalDateTime occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private AdminAccessEventStatus status;

    @Column(name = "reason", length = 255)
    private String reason;

    /**
     * Updates the access audit event value.
     *
     * @param adminId administrator account that made or received the access decision
     */
    public void setAdminId(Long adminId) {
        this.adminId = adminId;
    }

    /**
     * Updates the access audit event value.
     *
     * @param deviceId device associated with the decision, when known
     */
    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    /**
     * Updates the access audit event value.
     *
     * @param browser bounded browser label associated with the decision
     */
    public void setBrowser(String browser) {
        this.browser = browser;
    }

    /**
     * Updates the access audit event value.
     *
     * @param sanitizedUserAgent sanitized user-agent value; do not pass an unbounded raw header
     */
    public void setSanitizedUserAgent(String sanitizedUserAgent) {
        this.sanitizedUserAgent = sanitizedUserAgent;
    }

    /**
     * Updates the access audit event value.
     *
     * @param ipFingerprint one-way client address fingerprint for correlation
     */
    public void setIpFingerprint(String ipFingerprint) {
        this.ipFingerprint = ipFingerprint;
    }

    /**
     * Updates the access audit event value.
     *
     * @param status recorded result of the access decision
     */
    public void setStatus(AdminAccessEventStatus status) {
        this.status = status;
    }

    /**
     * Updates the access audit event value.
     *
     * @param reason bounded explanation suitable for an audit trail
     */
    public void setReason(String reason) {
        this.reason = reason;
    }
}
