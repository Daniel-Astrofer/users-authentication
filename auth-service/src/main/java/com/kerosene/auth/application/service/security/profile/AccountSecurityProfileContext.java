package com.kerosene.auth.application.service.security.profile;

import com.kerosene.auth.dto.UserDTO;
import com.kerosene.auth.model.enums.AccountSecurityType;

/** Immutable view of the user and effective security mode shared across normalization handlers. */
public class AccountSecurityProfileContext {

    /** User DTO whose security thresholds and share counts may be normalized by the chain. */
    private final UserDTO user;
    /** Security mode resolved once at context creation, defaulting missing legacy data to STANDARD. */
    private final AccountSecurityType securityType;

    /**
     * Captures the user and resolves its effective mode for the current chain execution.
     * A missing mode from legacy data is treated as STANDARD; the DTO itself remains mutable for normalization.
     *
     * @param user account DTO being validated and normalized
     */
    public AccountSecurityProfileContext(UserDTO user) {
        this.user = user;
        this.securityType = user.getAccountSecurity() != null
                ? user.getAccountSecurity()
                : AccountSecurityType.STANDARD;
    }

    /**
     * Returns the mutable DTO being normalized by the handlers.
     *
     * @return user account DTO
     */
    public UserDTO getUser() {
        return user;
    }

    /**
     * Returns the effective mode captured at construction so all handlers use one consistent value.
     *
     * @return account security mode
     */
    public AccountSecurityType getSecurityType() {
        return securityType;
    }
}
