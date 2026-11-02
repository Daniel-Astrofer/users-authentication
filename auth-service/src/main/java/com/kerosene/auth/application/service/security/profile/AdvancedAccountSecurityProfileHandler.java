package com.kerosene.auth.application.service.security.profile;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** First chain stage: ensures advanced modes are enabled before applying mode-specific rules. */
@Component
@Order(5)
public class AdvancedAccountSecurityProfileHandler extends AbstractAccountSecurityProfileHandler {

    /** Feature gate shared with other flows that expose advanced security modes. */
    private final AdvancedAccountSecurityAvailability availability;

    /**
     * Injects the authoritative feature availability check.
     *
     * @param availability feature gate shared by account profile and related security flows
     */
    public AdvancedAccountSecurityProfileHandler(AdvancedAccountSecurityAvailability availability) {
        this.availability = availability;
    }

    /**
     * Verifies mode availability, then continues to the next profile handler.
     *
     * @param context current account profile and resolved mode
     */
    @Override
    public void handle(AccountSecurityProfileContext context) {
        availability.assertSupported(context.getSecurityType());
        handleNext(context);
    }
}
