package com.kerosene.auth.dto;

import com.kerosene.auth.model.enums.AccountSecurityType;

/** Request to change the account security mode and its mode-specific thresholds. */
public class AccountSecurityUpdateRequestDTO {

    /** Creates an empty request bean for JSON deserialization. */
    public AccountSecurityUpdateRequestDTO() {
    }

    /**
     * Requested mode; STANDARD is selected when a request omits this property.
     */
    private AccountSecurityType accountSecurity = AccountSecurityType.STANDARD;
    /**
     * Total Shamir shares to create when selecting SHAMIR mode.
     */
    private Integer shamirTotalShares;
    /**
     * Minimum Shamir shares required to recover the secret.
     */
    private Integer shamirThreshold;
    /**
     * Required multisig factor count, validated by the profile normalization chain.
     */
    private Integer multisigThreshold;

    /**
     * Returns the requested security mode.
     * @return account security mode
     */
    public AccountSecurityType getAccountSecurity() {
        return accountSecurity;
    }

    /**
     * Sets the requested security mode.
     * @param accountSecurity selected mode
     */
    public void setAccountSecurity(AccountSecurityType accountSecurity) {
        this.accountSecurity = accountSecurity;
    }

    /**
     * Returns the total Shamir share count.
     * @return share count or null when not supplied
     */
    public Integer getShamirTotalShares() {
        return shamirTotalShares;
    }

    /**
     * Sets the total Shamir share count.
     * @param shamirTotalShares requested share count
     */
    public void setShamirTotalShares(Integer shamirTotalShares) {
        this.shamirTotalShares = shamirTotalShares;
    }

    /**
     * Returns the Shamir reconstruction threshold.
     * @return threshold or null when not supplied
     */
    public Integer getShamirThreshold() {
        return shamirThreshold;
    }

    /**
     * Sets the Shamir reconstruction threshold.
     * @param shamirThreshold requested threshold
     */
    public void setShamirThreshold(Integer shamirThreshold) {
        this.shamirThreshold = shamirThreshold;
    }

    /**
     * Returns the multisig factor threshold.
     * @return factor threshold or null when not supplied
     */
    public Integer getMultisigThreshold() {
        return multisigThreshold;
    }

    /**
     * Sets the multisig factor threshold.
     * @param multisigThreshold requested factor threshold
     */
    public void setMultisigThreshold(Integer multisigThreshold) {
        this.multisigThreshold = multisigThreshold;
    }
}
