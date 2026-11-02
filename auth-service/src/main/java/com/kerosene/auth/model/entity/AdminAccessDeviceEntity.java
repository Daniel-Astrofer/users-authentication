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
import jakarta.persistence.UniqueConstraint;
import java.time.LocalDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import com.kerosene.auth.model.enums.AdminAccessDeviceStatus;

/**
 * Registered device identity used as an approval factor for administrator access.
 * A unique constraint prevents duplicate enrollment of one device for the same account;
 * client metadata is informational and must not be treated as cryptographic device proof.
 */
@Entity
@Table(
        schema = "auth",
        name = "admin_access_devices",
        uniqueConstraints = @UniqueConstraint(name = "uk_admin_access_device_user_device", columnNames = {"user_id", "device_id"}))
public class AdminAccessDeviceEntity {

    /** Creates an empty entity for JPA materialization and subsequent field population. */
    public AdminAccessDeviceEntity() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserDataBase user;

    @Column(name = "device_id", nullable = false, length = 128)
    private String deviceId;

    @Column(name = "device_name", length = 255)
    private String deviceName;

    @Column(name = "browser", length = 128)
    private String browser;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private AdminAccessDeviceStatus status = AdminAccessDeviceStatus.PENDING;

    @CreationTimestamp
    @Column(name = "first_access_at", nullable = false, updatable = false)
    private LocalDateTime firstAccessAt;

    @Column(name = "last_access_at")
    private LocalDateTime lastAccessAt;

    /**
     * Reads the device enrollment value.
     *
     * @return persistence identifier generated for this enrollment
     */
    public UUID getId() {
        return id;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return account that owns this administrator device enrollment
     */
    public UserDataBase getUser() {
        return user;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param user account that owns the device enrollment
     */
    public void setUser(UserDataBase user) {
        this.user = user;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return stable client-provided identifier used to locate this enrollment
     */
    public String getDeviceId() {
        return deviceId;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param deviceId stable identifier reported by the enrolled client
     */
    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return optional human-readable device label
     */
    public String getDeviceName() {
        return deviceName;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param deviceName optional label shown to administrators when reviewing devices
     */
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return browser family captured during enrollment, if available
     */
    public String getBrowser() {
        return browser;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param browser bounded browser label captured during enrollment
     */
    public void setBrowser(String browser) {
        this.browser = browser;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return user-agent captured during enrollment, if available
     */
    public String getUserAgent() {
        return userAgent;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param userAgent bounded user-agent captured for administrator review
     */
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return enrollment trust state controlling whether this device may approve access
     */
    public AdminAccessDeviceStatus getStatus() {
        return status;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param status new lifecycle state for this enrolled device
     */
    public void setStatus(AdminAccessDeviceStatus status) {
        this.status = status;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return database-generated time when the enrollment row was first created
     */
    public LocalDateTime getFirstAccessAt() {
        return firstAccessAt;
    }

    /**
     * Reads the device enrollment value.
     *
     * @return most recent access time recorded for this device, if any
     */
    public LocalDateTime getLastAccessAt() {
        return lastAccessAt;
    }

    /**
     * Updates the device enrollment value.
     *
     * @param lastAccessAt most recent access time observed by the service
     */
    public void setLastAccessAt(LocalDateTime lastAccessAt) {
        this.lastAccessAt = lastAccessAt;
    }
}
