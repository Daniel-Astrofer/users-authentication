package com.kerosene.auth.application.service.recovery.start.chain;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.kerosene.auth.application.service.recovery.RecoveryRateLimitService;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;

/** Second recovery-start step: enforces username/client start-attempt limits. */
@Component
@Order(20)
public class EmergencyRecoveryStartRateLimitHandler extends AbstractEmergencyRecoveryStartHandler {

    /** Redis-backed policy for start and failure counters. */
    private final RecoveryRateLimitService rateLimitService;

    /**
     * Creates the recovery-start throttle handler.
     * @param rateLimitService recovery throttle policy
     */
    public EmergencyRecoveryStartRateLimitHandler(RecoveryRateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    /**
     * Rejects exhausted clients before PoW or user lookup, then continues.
     * @param context validated request identity and client fingerprint
     */
    @Override
    public void handle(EmergencyRecoveryStartContext context) {
        rateLimitService.enforceStartAttempt(context.normalizedUsername(), context.clientFingerprint());
        handleNext(context);
    }
}
