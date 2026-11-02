package com.kerosene.auth.model.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import com.kerosene.auth.model.contracts.UserDB;
import com.kerosene.auth.model.enums.AccountSecurityType;
import com.kerosene.auth.model.enums.UserRole;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.time.LocalDateTime;

@Entity()
@Table(schema = "auth", name = "users_credentials", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "voucher_id" }) }, indexes = {
                @Index(name = "idx_users_username", columnList = "username", unique = true) })
public class UserDataBase implements UserDB {

    public UserDataBase() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Invalidates older account sessions whenever emergency credentials are replaced. */
    @Column(name = "credential_epoch", nullable = false)
    private long credentialEpoch;

    /** Prevents unrelated stale account writes from undoing a concurrent recovery. */
    @Version
    @Column(name = "record_version", nullable = false)
    private long recordVersion;

    @JsonIgnore
    public long getCredentialEpoch() { return credentialEpoch; }

    public void advanceCredentialEpoch() { credentialEpoch = Math.addExact(credentialEpoch, 1L); }

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Convert(converter = com.kerosene.security.persistence.StringCryptoConverter.class)
    @Column(name = "password_hash")
    private String passwordHash;

    @Convert(converter = com.kerosene.security.persistence.StringCryptoConverter.class)
    @Column(name = "totp_secret")
    private String totpSecret;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

    @Column(name = "is_active", nullable = false, columnDefinition = "boolean default false")
    private Boolean isActive = false;

    @Column(name = "failed_login_attempts", nullable = false, columnDefinition = "integer default 0")
    private Integer failedLoginAttempts = 0;

    /**
     * The account security mode chosen at signup.
     * Stored as a VARCHAR using the enum name.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "account_security", nullable = false, length = 20, columnDefinition = "VARCHAR(20) DEFAULT 'STANDARD'")
    private AccountSecurityType accountSecurity = AccountSecurityType.STANDARD;

    @Column(name = "passkey_transaction_auth", nullable = false, columnDefinition = "boolean default false")
    private Boolean passkeyEnabledForTransactions = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 32, columnDefinition = "VARCHAR(32) DEFAULT 'USER'")
    private UserRole role = UserRole.USER;

    /**
     * AES-256-GCM encrypted co-signer secret (Base64-encoded IV + ciphertext).
     * Only populated for SHAMIR and MULTISIG_2FA modes.
     * NEVER exposed via any API or DTO — annotated @JsonIgnore as a safety net.
     */
    @JsonIgnore
    @Column(name = "platform_cosigner_secret", columnDefinition = "TEXT")
    private String platformCosignerSecret;

    @Column(name = "shamir_total_shares")
    private Integer shamirTotalShares;

    @Column(name = "shamir_threshold")
    private Integer shamirThreshold;

    @Column(name = "multisig_threshold", nullable = false, columnDefinition = "integer default 2")
    private Integer multisigThreshold = 2;

    @OneToOne
    @JoinColumn(name = "voucher_id", referencedColumnName = "id", unique = true)
    private Voucher voucher;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_backup_codes", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "code_hash")
    private java.util.List<String> backupCodes = new java.util.ArrayList<>();

    public Voucher getVoucher() {
        return voucher;
    }

    public void setVoucher(Voucher voucher) {
        this.voucher = voucher;
    }

    @Override
    public String getTOTPSecret() {
        return totpSecret;
    }

    @Override
    public void setTOTPSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    @Override
    public String getPasswordHash() {
        return passwordHash;
    }

    @Override
    public Long getId() {
        return this.id;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public LocalDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(LocalDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public LocalDateTime getActivatedAt() {
        return activatedAt;
    }

    public void setActivatedAt(LocalDateTime activatedAt) {
        this.activatedAt = activatedAt;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public Integer getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(Integer failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public AccountSecurityType getAccountSecurity() {
        return accountSecurity;
    }

    public void setAccountSecurity(AccountSecurityType accountSecurity) {
        this.accountSecurity = accountSecurity;
    }

    /** Returns the AES-GCM ciphertext. Never expose this via API. */
    public String getPlatformCosignerSecret() {
        return platformCosignerSecret;
    }

    public void setPlatformCosignerSecret(String platformCosignerSecret) {
        this.platformCosignerSecret = platformCosignerSecret;
    }

    public Integer getShamirTotalShares() {
        return shamirTotalShares;
    }

    public void setShamirTotalShares(Integer shamirTotalShares) {
        this.shamirTotalShares = shamirTotalShares;
    }

    public Integer getShamirThreshold() {
        return shamirThreshold;
    }

    public void setShamirThreshold(Integer shamirThreshold) {
        this.shamirThreshold = shamirThreshold;
    }

    public Integer getMultisigThreshold() {
        return multisigThreshold;
    }

    public void setMultisigThreshold(Integer multisigThreshold) {
        this.multisigThreshold = multisigThreshold;
    }

    public Boolean getPasskeyEnabledForTransactions() {
        return passkeyEnabledForTransactions;
    }

    public void setPasskeyEnabledForTransactions(Boolean passkeyEnabledForTransactions) {
        this.passkeyEnabledForTransactions = passkeyEnabledForTransactions;
    }

    public UserRole getRole() {
        return role != null ? role : UserRole.USER;
    }

    public void setRole(UserRole role) {
        this.role = role != null ? role : UserRole.USER;
    }

    public java.util.List<String> getBackupCodes() {
        return backupCodes;
    }

    public void setBackupCodes(java.util.List<String> backupCodes) {
        this.backupCodes = backupCodes;
    }

    public boolean hasTotpEnabled() {
        return totpSecret != null && !totpSecret.isBlank();
    }
}
