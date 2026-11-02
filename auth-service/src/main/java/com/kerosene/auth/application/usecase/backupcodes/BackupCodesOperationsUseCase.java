package com.kerosene.auth.application.usecase.backupcodes;

import org.springframework.stereotype.Component;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.account.BackupCodeService;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationPort;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationRequest;
import com.kerosene.auth.dto.BackupCodesStatusDTO;

/** Reads backup-code status and authorizes regeneration through the account-security factor policy. */
@Component
public class BackupCodesOperationsUseCase {

    /** Stable public error text returned when any required regeneration factor is rejected. */
    private static final String REGENERATION_AUTHORIZATION_FAILURE =
            "Unable to authorize backup code regeneration.";

    /** Backup-code lifecycle service that reports and regenerates stored codes. */
    private final BackupCodeService backupCodeService;
    /** Applies transaction-level authentication requirements before sensitive code rotation. */
    private final TransactionalAuthenticationPort transactionalAuthenticationPort;

    /**
     * Creates the backup-code operation with factor authorization and lifecycle boundaries.
     *
     * @param backupCodeService backup-code status and regeneration service
     * @param transactionalAuthenticationPort authorization policy for account security changes
     */
    public BackupCodesOperationsUseCase(
            BackupCodeService backupCodeService,
            TransactionalAuthenticationPort transactionalAuthenticationPort) {
        this.backupCodeService = backupCodeService;
        this.transactionalAuthenticationPort = transactionalAuthenticationPort;
    }

    /**
     * Returns backup-code availability and lifecycle status for the account.
     *
     * @param userId account identifier
     * @return backup-code status projection without raw codes or hashes
     */
    public BackupCodesStatusDTO getStatus(Long userId) {
        return backupCodeService.getStatus(userId);
    }

    /**
     * Authorizes rotation with the account-security factors, then replaces the backup codes.
     * Validation failures are converted to one generic invalid-credentials message.
     *
     * @param userId account identifier
     * @param totpCode optional submitted TOTP code
     * @param passkeyAssertionJson optional passkey assertion JSON
     * @param confirmationPassphrase optional confirmation passphrase
     * @return status of the newly generated code set
     * @throws AuthExceptions.InvalidCredentials when factor authorization fails
     */
    public BackupCodesStatusDTO regenerate(
            Long userId,
            String totpCode,
            String passkeyAssertionJson,
            String confirmationPassphrase) {
        try {
            transactionalAuthenticationPort.authorize(TransactionalAuthenticationRequest.accountSecurityChange(
                    userId,
                    totpCode,
                    passkeyAssertionJson,
                    confirmationPassphrase));
        } catch (AuthExceptions.AuthValidationException exception) {
            throw new AuthExceptions.InvalidCredentials(REGENERATION_AUTHORIZATION_FAILURE);
        }

        return backupCodeService.regenerate(userId);
    }
}
