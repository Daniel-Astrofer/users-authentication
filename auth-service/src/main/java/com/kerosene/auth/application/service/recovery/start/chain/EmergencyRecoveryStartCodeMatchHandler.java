package com.kerosene.auth.application.service.recovery.start.chain;

import java.util.List;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.recovery.RecoveryCodeService;
import com.kerosene.auth.application.service.recovery.RecoveryRateLimitService;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;

/** Final recovery-start proof step: matches every normalized code and records or clears failures. */
@Component
@Order(50)
public class EmergencyRecoveryStartCodeMatchHandler extends AbstractEmergencyRecoveryStartHandler {

    /** Matches submitted normalized codes against stored hashes. */
    private final RecoveryCodeService recoveryCodeService;
    /** Tracks failed recovery-code attempts and clears counters on success. */
    private final RecoveryRateLimitService rateLimitService;

    /**
     * Creates the recovery-code proof matcher.
     * @param recoveryCodeService code-to-hash matcher
     * @param rateLimitService attempt tracking policy
     */
    public EmergencyRecoveryStartCodeMatchHandler(RecoveryCodeService recoveryCodeService,
            RecoveryRateLimitService rateLimitService) {
        this.recoveryCodeService = recoveryCodeService;
        this.rateLimitService = rateLimitService;
    }

    /**
     * Requires every requested code to match; failure records abuse counters and rejects generically.
     * @param context validated user and normalized recovery-code candidates
     */
    @Override
    public void handle(EmergencyRecoveryStartContext context) {
        List<String> matchedHashes = recoveryCodeService.matchRecoveryCodes(
                context.normalizedRecoveryCodes(),
                context.user().getBackupCodes());
        if (matchedHashes.size() != context.normalizedRecoveryCodes().size()) {
            rateLimitService.registerFailure(context.normalizedUsername(), context.clientFingerprint());
            throw new AuthExceptions.RecoveryRejectedException(
                    "Recovery request rejected. Verify the recovery codes and retry.");
        }

        rateLimitService.clearFailures(context.normalizedUsername(), context.clientFingerprint());
        context.setMatchedRecoveryCodeHashes(matchedHashes);
        handleNext(context);
    }
}
