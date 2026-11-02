package com.kerosene.auth.application.service.recovery.start.chain;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.pow.PowService;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;

/** Third recovery-start step: verifies the required proof-of-work challenge and nonce. */
@Component
@Order(30)
public class EmergencyRecoveryStartProofOfWorkHandler extends AbstractEmergencyRecoveryStartHandler {

    /** Verifies challenge freshness and proof-of-work difficulty. */
    private final PowService powService;

    /**
     * Creates the PoW validation step.
     * @param powService challenge verifier
     */
    public EmergencyRecoveryStartProofOfWorkHandler(PowService powService) {
        this.powService = powService;
    }

    /**
     * Rejects invalid/expired proof and proceeds only after successful verification.
     * @param context request containing challenge and nonce
     */
    @Override
    public void handle(EmergencyRecoveryStartContext context) {
        if (!powService.verifyChallenge(context.request().getChallenge(), context.request().getNonce())) {
            throw new AuthExceptions.InvalidCredentials(
                    "Invalid or expired Proof of Work. Please request a new challenge and calculate the correct nonce.");
        }
        handleNext(context);
    }
}
