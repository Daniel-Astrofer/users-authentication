package com.kerosene.auth.application.usecase.security;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.account.AppPinService;
import com.kerosene.auth.application.service.passkey.PasskeyInventoryService;
import com.kerosene.auth.dto.AccountSecurityProfileDTO;
import com.kerosene.auth.dto.PasskeyInventoryDTO;
import com.kerosene.auth.model.entity.UserDataBase;

/** Builds the account security profile from passkey and device-scoped app-PIN state. */
@Component
public class GetAccountSecurityProfileUseCase {

    /** Projects registered and login-usable passkey metadata. */
    private final PasskeyInventoryService passkeyInventoryService;
    /** Retrieves PIN configuration for the supplied device context. */
    private final AppPinService appPinService;

    /**
     * Creates the account security profile query.
     * @param passkeyInventoryService passkey inventory projection service
     * @param appPinService device-scoped PIN status service
     */
    public GetAccountSecurityProfileUseCase(
            PasskeyInventoryService passkeyInventoryService,
            AppPinService appPinService) {
        this.passkeyInventoryService = passkeyInventoryService;
        this.appPinService = appPinService;
    }

    /**
     * Combines account fields, passkey inventory, and current-device PIN status into one profile.
     * @param user account whose profile is requested
     * @param deviceHash device reference used for PIN status
     * @return assembled account security profile
     */
    public AccountSecurityProfileDTO execute(UserDataBase user, String deviceHash) {
        PasskeyInventoryDTO passkeys = passkeyInventoryService.inventoryFor(user);
        return AccountSecurityProfileDTO.fromUser(
                user,
                passkeys.passkeyRegistered(),
                passkeys,
                appPinService.getStatus(user, deviceHash));
    }
}
