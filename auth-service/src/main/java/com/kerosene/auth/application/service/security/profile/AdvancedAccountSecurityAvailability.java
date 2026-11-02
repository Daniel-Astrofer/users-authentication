package com.kerosene.auth.application.service.security.profile;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.model.enums.AccountSecurityType;

/** Central feature gate for Shamir and multi-factor multisig account modes. */
@Component
public class AdvancedAccountSecurityAvailability {

    /** Whether this build is configured to accept advanced account security modes. */
    private final boolean advancedModesEnabled;

    /**
     * Captures the deployment's advanced-mode feature flag.
     *
     * @param advancedModesEnabled value of {@code account.security.advanced-modes-enabled}
     */
    public AdvancedAccountSecurityAvailability(
            @Value("${account.security.advanced-modes-enabled:false}") boolean advancedModesEnabled) {
        this.advancedModesEnabled = advancedModesEnabled;
    }

    /**
     * Reports whether advanced modes are enabled in this deployment.
     *
     * @return configured feature state
     */
    public boolean isEnabled() {
        return advancedModesEnabled;
    }

    /**
     * Rejects SHAMIR and MULTISIG_2FA when the feature flag is disabled; STANDARD is always allowed.
     *
     * @param accountSecurityType requested account security mode
     * @throws AuthExceptions.InvalidCredentials when an advanced mode is unavailable
     */
    public void assertSupported(AccountSecurityType accountSecurityType) {
        if (accountSecurityType == AccountSecurityType.SHAMIR
                || accountSecurityType == AccountSecurityType.MULTISIG_2FA) {
            if (!advancedModesEnabled) {
                throw new AuthExceptions.InvalidCredentials(
                        "Advanced account security modes are not available in this build yet.");
            }
        }
    }
}
