package com.kerosene.auth.application.usecase.totp;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationPort;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationRequest;
import com.kerosene.auth.application.service.account.TotpManagementService;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.auth.dto.TotpSetupResponseDTO;

/** Exposes TOTP setup, confirmation, and disablement operations for an account. */
@Component
public class TotpOperationsUseCase {

    /** Service implementing the TOTP enrollment and lifecycle policy. */
    private final TotpManagementService totpManagementService;
    /** Verifies account-security factors before removing an authenticator. */
    private final TransactionalAuthenticationPort transactionalAuthenticationPort;

    /** Creates the TOTP operations facade. */
    /** @param totpManagementService TOTP lifecycle service
     * @param transactionalAuthenticationPort account-security authorization boundary */
    public TotpOperationsUseCase(TotpManagementService totpManagementService,
            TransactionalAuthenticationPort transactionalAuthenticationPort) {
        this.totpManagementService = totpManagementService;
        this.transactionalAuthenticationPort = transactionalAuthenticationPort;
    }

    /** Begins TOTP setup and returns enrollment material. */
    /** @param userId account identifier */
    /** @return setup response containing client enrollment data */
    public TotpSetupResponseDTO setup(Long userId) {
        return totpManagementService.beginSetup(userId);
    }

    /** Confirms TOTP enrollment using a generated authenticator code. */
    /** @param userId account identifier */
    /** @param totpCode code submitted for setup verification */
    /** @return backup-code status after setup verification */
    public BackupCodesStatusDTO verify(Long userId, String totpCode) {
        return totpManagementService.verifySetup(userId, totpCode);
    }

    /** Disables TOTP for the account through the lifecycle service. */
    /** @param userId account identifier */
    @Transactional
    public void disable(Long userId) {
        disable(userId, null, null, null);
    }

    /** Removes TOTP only after the current account's security policy authorizes it.
     * @param userId authenticated owner
     * @param totpCode current authenticator factor when required
     * @param passkeyAssertionJson one-use device/passkey proof
     * @param confirmationPassphrase account confirmation, preserving spaces
     */
    @Transactional
    public void disable(Long userId, String totpCode, String passkeyAssertionJson,
            String confirmationPassphrase) {
        transactionalAuthenticationPort.authorize(TransactionalAuthenticationRequest.accountSecurityChange(
                userId, totpCode, passkeyAssertionJson, confirmationPassphrase));
        totpManagementService.disable(userId);
    }
}
