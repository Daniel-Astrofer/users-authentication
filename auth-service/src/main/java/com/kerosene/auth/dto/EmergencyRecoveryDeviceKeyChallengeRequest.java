package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Requests a fresh enrollment challenge only after possession of the recovery session and new TOTP. */
public class EmergencyRecoveryDeviceKeyChallengeRequest {
    private String recoverySessionId;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String totpCode;

    public String getRecoverySessionId() { return recoverySessionId; }
    public void setRecoverySessionId(String recoverySessionId) { this.recoverySessionId = recoverySessionId; }
    public String getTotpCode() { return totpCode; }
    public void setTotpCode(String totpCode) { this.totpCode = totpCode; }
}
