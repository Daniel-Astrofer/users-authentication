package com.kerosene.auth.application.service.recovery.start.chain;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.kerosene.auth.application.service.authentication.contracts.SignupVerifier;
import com.kerosene.auth.application.service.recovery.RecoveryCodeService;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;

/** First recovery-start step: validates replacement credentials, distinct recovery proofs, and PoW fields. */
@Component
@Order(10)
public class EmergencyRecoveryStartRequestValidationHandler extends AbstractEmergencyRecoveryStartHandler {

    /** Signup rules reused for username and replacement passphrase policy. */
    private final SignupVerifier signupVerifier;
    /** Normalizes and validates the submitted recovery-code list. */
    private final RecoveryCodeService recoveryCodeService;

    /** Minimum number of distinct backup recovery codes required to start recovery. */
    @Value("${auth.recovery.required-backup-codes:3}")
    private int requiredRecoveryCodes;

    /**
     * Creates request validation with signup credential and recovery-code policies.
     * @param signupVerifier username and passphrase validator
     * @param recoveryCodeService recovery-code normalization service
     */
    public EmergencyRecoveryStartRequestValidationHandler(SignupVerifier signupVerifier,
            RecoveryCodeService recoveryCodeService) {
        this.signupVerifier = signupVerifier;
        this.recoveryCodeService = recoveryCodeService;
    }

    /**
     * Validates request presence, account/passphrase rules, code count, and PoW challenge fields.
     * @param context chain context receiving normalized username and recovery codes
     */
    @Override
    public void handle(EmergencyRecoveryStartContext context) {
        EmergencyRecoveryStartRequest request = context.request();
        if (request == null) {
            throw new IllegalArgumentException("Recovery request body is required.");
        }

        String normalizedUsername = normalizeUsername(request.getUsername());
        signupVerifier.checkUsernameNotNull(normalizedUsername);
        signupVerifier.checkUsernameFormat(normalizedUsername);
        signupVerifier.checkUsernameLength(normalizedUsername);
        signupVerifier.checkPassphraseNotNull(request.getNewPassphrase());
        signupVerifier.checkPassphraseLength(request.getNewPassphrase());
        char[] passphraseCopy = copyCharArray(request.getNewPassphrase());
        try {
            signupVerifier.checkPassphraseBip39(passphraseCopy);
        } finally {
            if (passphraseCopy != null) {
                java.util.Arrays.fill(passphraseCopy, '\0');
            }
        }

        List<String> normalizedCodes = recoveryCodeService.normalizeRecoveryCodes(request.getRecoveryCodes());
        if (normalizedCodes.size() < requiredRecoveryCodes) {
            throw new IllegalArgumentException(
                    "At least " + requiredRecoveryCodes + " distinct recovery codes are required.");
        }

        if (request.getChallenge() == null || request.getChallenge().isBlank()
                || request.getNonce() == null || request.getNonce().isBlank()) {
            throw new IllegalArgumentException("Proof of Work challenge and nonce are required.");
        }

        context.setNormalizedUsername(normalizedUsername);
        context.setNormalizedRecoveryCodes(normalizedCodes);
        handleNext(context);
    }

    /**
     * Trims and lowercases a username for identity lookup and rate-limit keys.
     * @param username submitted username
     * @return normalized username or null
     */
    private String normalizeUsername(String username) {
        return username == null ? null : username.trim().toLowerCase();
    }

    /**
     * Makes a private mutable copy so passphrase policy checks do not mutate the request buffer.
     * @param input request passphrase
     * @return copied character array or null
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
