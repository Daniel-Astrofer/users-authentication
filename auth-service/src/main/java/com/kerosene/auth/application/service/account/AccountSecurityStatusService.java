package com.kerosene.auth.application.service.account;

import org.springframework.stereotype.Service;
import com.kerosene.auth.application.service.passkey.PasskeyInventoryService;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.dto.AccountSecurityStatusDTO;
import com.kerosene.auth.dto.PasskeyInventoryDTO;
import com.kerosene.auth.model.entity.UserDataBase;

/** Builds the account's consolidated authentication and recovery readiness status. */
@Service
public class AccountSecurityStatusService {

    /** Loads the persisted account used to derive current security state. */
    private final UserServiceContract userService;
    /** Projects registered and usable passkey details for the response. */
    private final PasskeyInventoryService passkeyInventoryService;

    /**
     * Creates the security status service.
     *
     * @param userService account lookup boundary
     * @param passkeyInventoryService passkey inventory projection service
     */
    public AccountSecurityStatusService(
            UserServiceContract userService,
            PasskeyInventoryService passkeyInventoryService) {
        this.userService = userService;
        this.passkeyInventoryService = passkeyInventoryService;
    }

    /**
     * Derives password, passkey, TOTP, backup-code, activation, and inbound-readiness flags.
     * Inbound receiving is blocked while TOTP is disabled, and inactive status is reflected in
     * both activation and receiving fields.
     *
     * @param userId account identifier
     * @return consolidated security status
     * @throws IllegalStateException when the authenticated account no longer exists
     */
    public AccountSecurityStatusDTO getStatus(Long userId) {
        UserDataBase user = userService.buscarPorId(userId)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found."));
        PasskeyInventoryDTO passkeys = passkeyInventoryService.inventoryFor(user);
        boolean passkeyRegistered = passkeys.passkeyRegistered();
        boolean totpEnabled = user.hasTotpEnabled();
        int backupCodesRemaining = user.getBackupCodes() != null ? user.getBackupCodes().size() : 0;

        return new AccountSecurityStatusDTO(
                user.getPasswordHash() != null && !user.getPasswordHash().isBlank(),
                passkeyRegistered,
                totpEnabled,
                backupCodesRemaining,
                !totpEnabled,
                !totpEnabled
                        ? "Conta nao protegida: ative o TOTP para reduzir o risco de perda ou tomada de conta."
                        : null,
                Boolean.TRUE.equals(user.getIsActive()),
                Boolean.TRUE.equals(user.getIsActive()),
                passkeys);
    }
}
