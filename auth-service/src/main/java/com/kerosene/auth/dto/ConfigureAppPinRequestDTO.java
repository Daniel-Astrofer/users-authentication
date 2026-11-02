package com.kerosene.auth.dto;

/** Input contract for enabling, disabling, or resetting application PIN protection. */
public class ConfigureAppPinRequestDTO {

    /** Creates an empty PIN configuration bean for JSON deserialization. */
    public ConfigureAppPinRequestDTO() {
    }

    /** whether PIN verification should be enabled or disabled */
    private Boolean enabled;
    /** new PIN value when configuring or changing the verifier */
    private String pin;
    /** existing PIN required when changing protected PIN settings */
    private String currentPin;
    /** TOTP proof used by flows that reset the PIN without the current PIN */
    private String totpCode;

    /**
     * Returns whether PIN verification should be enabled or disabled
     * @return requested enabled state
     */
    public Boolean getEnabled() { return enabled; }

    /**
     * Sets whether PIN verification should be enabled or disabled
     * @param enabled requested enabled state
     */
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    /**
     * Returns new PIN value when configuring or changing the verifier
     * @return new PIN
     */
    public String getPin() { return pin; }

    /**
     * Sets new PIN value when configuring or changing the verifier
     * @param pin new PIN
     */
    public void setPin(String pin) { this.pin = pin; }

    /**
     * Returns existing PIN required when changing protected PIN settings
     * @return current PIN
     */
    public String getCurrentPin() { return currentPin; }

    /**
     * Sets existing PIN required when changing protected PIN settings
     * @param currentPin current PIN
     */
    public void setCurrentPin(String currentPin) { this.currentPin = currentPin; }

    /**
     * Returns tOTP proof used by flows that reset the PIN without the current PIN
     * @return TOTP code
     */
    public String getTotpCode() { return totpCode; }

    /**
     * Sets tOTP proof used by flows that reset the PIN without the current PIN
     * @param totpCode TOTP code
     */
    public void setTotpCode(String totpCode) { this.totpCode = totpCode; }

}
