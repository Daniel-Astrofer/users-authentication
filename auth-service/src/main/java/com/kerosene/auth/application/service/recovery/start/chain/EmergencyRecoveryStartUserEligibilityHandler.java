package com.kerosene.auth.application.service.recovery.start.chain;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import com.kerosene.auth.application.service.recovery.RecoveryCodeService;
import com.kerosene.auth.application.service.recovery.RecoveryRateLimitService;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.model.entity.UserDataBase;

/** Fourth recovery-start step: resolves eligible accounts and prevents reusing the current passphrase. */
@Component
@Order(40)
public class EmergencyRecoveryStartUserEligibilityHandler extends AbstractEmergencyRecoveryStartHandler {

    /** Outbound account lookup boundary. */
    private final AuthUserGateway userGateway;
    /** Argon2-qualified verifier for comparing the proposed passphrase with the current hash. */
    private final Hasher hasher;
    /** Burns candidate checks and normalizes recovery-code lists. */
    private final RecoveryCodeService recoveryCodeService;
    /** Records failed recovery attempts scoped to username and client fingerprint. */
    private final RecoveryRateLimitService rateLimitService;

    /**
     * Creates the eligibility step with identity, secret, and abuse-control boundaries.
     * @param userGateway account lookup
     * @param hasher Argon2 passphrase verifier
     * @param recoveryCodeService recovery code utilities
     * @param rateLimitService recovery attempt tracking
     */
    public EmergencyRecoveryStartUserEligibilityHandler(AuthUserGateway userGateway,
            @Qualifier("Argon2Hasher") Hasher hasher,
            RecoveryCodeService recoveryCodeService,
            RecoveryRateLimitService rateLimitService) {
        this.userGateway = userGateway;
        this.hasher = hasher;
        this.recoveryCodeService = recoveryCodeService;
        this.rateLimitService = rateLimitService;
    }

    /**
     * Loads the owner, applies generic rejection for absent/insufficient accounts, and rejects reused passphrases.
     * @param context validated request and normalized user identity
     */
    @Override
    public void handle(EmergencyRecoveryStartContext context) {
        UserDataBase user = userGateway.findByUsername(context.normalizedUsername());
        if (user == null || user.getBackupCodes() == null
                || user.getBackupCodes().size() < context.normalizedRecoveryCodes().size()) {
            recoveryCodeService.burnRecoveryCodeChecks(context.normalizedRecoveryCodes());
            rateLimitService.registerFailure(context.normalizedUsername(), context.clientFingerprint());
            throw new AuthExceptions.RecoveryRejectedException(
                    "Recovery request rejected. Verify the recovery codes and retry.");
        }

        char[] newPassphraseCopy = copyCharArray(context.request().getNewPassphrase());
        try {
            if (Boolean.TRUE.equals(hasher.verify(newPassphraseCopy, user.getPassphrase()))) {
                throw new AuthExceptions.InvalidPassphrase(
                        "The new passphrase must be different from the current passphrase.");
            }
        } finally {
            if (newPassphraseCopy != null) {
                java.util.Arrays.fill(newPassphraseCopy, '\0');
            }
        }

        context.setUser(user);
        handleNext(context);
    }

    /**
     * Copies a passphrase into a temporary mutable buffer for verification and later zeroing.
     * @param input request passphrase
     * @return independent copy or null
     */
    private char[] copyCharArray(char[] input) {
        if (input == null) {
            return null;
        }
        char[] copy = new char[input.length];
        System.arraycopy(input, 0, copy, 0, input.length);
        return copy;
    }
}
