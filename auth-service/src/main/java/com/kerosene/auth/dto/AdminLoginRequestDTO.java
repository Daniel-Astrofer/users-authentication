package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Arrays;

/** Input contract for administrator authentication, including secret proof and device context. */
public class AdminLoginRequestDTO {

    /** Creates an empty login request bean for JSON deserialization. */
    public AdminLoginRequestDTO() {
    }

    /** Administrator account name used to locate the credential record. */
    private String username;

    /** Sensitive administrator passphrase; JSON accepts both password and legacy passphrase property names. */
    @JsonAlias({"passphrase"})
    @JsonProperty("password")
    private char[] password;

    /** Write-only proof that the client possesses the administrator key. */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String adminKeyProof;

    /** Stable identity of the device initiating administrator login. */
    private String deviceId;

    /** Human-readable label for the requesting device. */
    private String deviceName;

    /** Browser identifier reported by the client. */
    private String browser;

    /** Client user-agent string recorded for access review. */
    private String userAgent;

    /** Operating system or platform family reported by the client. */
    private String platform;

    /**
     * Returns administrator account name used to locate the credential record.
     * @return account username
     */
    public String getUsername() { return username; }

    /**
     * Sets administrator account name used to locate the credential record.
     * @param username account username
     */
    public void setUsername(String username) { this.username = username; }

    /**
     * Returns sensitive administrator passphrase; JSON accepts both password and legacy passphrase property names.
     * @return password character array
     */
    public char[] getPassword() { return password; }

    /**
     * Sets sensitive administrator passphrase; JSON accepts both password and legacy passphrase property names.
     * @param password password character array
     */
    public void setPassword(char[] password) { this.password = password; }

    /**
     * Returns write-only proof that the client possesses the administrator key.
     * @return administrator key proof
     */
    public String getAdminKeyProof() { return adminKeyProof; }

    /**
     * Sets write-only proof that the client possesses the administrator key.
     * @param adminKeyProof administrator key proof
     */
    public void setAdminKeyProof(String adminKeyProof) { this.adminKeyProof = adminKeyProof; }

    /**
     * Returns stable identity of the device initiating administrator login.
     * @return device identifier
     */
    public String getDeviceId() { return deviceId; }

    /**
     * Sets stable identity of the device initiating administrator login.
     * @param deviceId device identifier
     */
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    /**
     * Returns human-readable label for the requesting device.
     * @return device name
     */
    public String getDeviceName() { return deviceName; }

    /**
     * Sets human-readable label for the requesting device.
     * @param deviceName device name
     */
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }

    /**
     * Returns browser identifier reported by the client.
     * @return browser identifier
     */
    public String getBrowser() { return browser; }

    /**
     * Sets browser identifier reported by the client.
     * @param browser browser identifier
     */
    public void setBrowser(String browser) { this.browser = browser; }

    /**
     * Returns client user-agent string recorded for access review.
     * @return user-agent value
     */
    public String getUserAgent() { return userAgent; }

    /**
     * Sets client user-agent string recorded for access review.
     * @param userAgent user-agent value
     */
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    /**
     * Returns operating system or platform family reported by the client.
     * @return platform identifier
     */
    public String getPlatform() { return platform; }

    /**
     * Sets operating system or platform family reported by the client.
     * @param platform platform identifier
     */
    public void setPlatform(String platform) { this.platform = platform; }

    /** Erases the in-memory passphrase buffer after authentication processing. */
    public void wipePassword() {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
