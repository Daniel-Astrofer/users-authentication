package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;

/** Fresh account factors and the replacement PIN for authenticated device-PIN recovery. */
public class RecoverAppPinRequestDTO {

    /** Account password; never included in a serialized response. */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private char[] password;
    /** Replacement PIN, restricted to exactly four ASCII digits. */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String newPin;
    /** Fresh assertion from an active device key already owned by this account. */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private DeviceKeyVerifyRequest deviceKey;

    /** Creates an empty request for JSON binding. */
    public RecoverAppPinRequestDTO() { }

    /** @return account password characters owned by this request */
    public char[] getPassword() { return password; }
    /** @param password account password characters to verify and wipe */
    public void setPassword(char[] password) { this.password = password; }
    /** @return requested replacement PIN */
    public String getNewPin() { return newPin; }
    /** @param newPin replacement PIN containing exactly four digits */
    public void setNewPin(String newPin) { this.newPin = newPin; }
    /** @return fresh registered-device assertion */
    public DeviceKeyVerifyRequest getDeviceKey() { return deviceKey; }
    /** @param deviceKey assertion over a one-use authentication challenge */
    public void setDeviceKey(DeviceKeyVerifyRequest deviceKey) { this.deviceKey = deviceKey; }
}
