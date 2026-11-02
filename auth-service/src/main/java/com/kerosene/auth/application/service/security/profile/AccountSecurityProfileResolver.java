package com.kerosene.auth.application.service.security.profile;

import org.springframework.stereotype.Service;

import com.kerosene.auth.dto.UserDTO;

/** Application-facing entry point for applying all account security profile rules to a user DTO. */
@Service
public class AccountSecurityProfileResolver {

    /** Ordered validation and normalization pipeline. */
    private final AccountSecurityProfileChain chain;

    /**
     * Injects the ordered chain that owns mode-specific profile rules.
     *
     * @param chain handlers sorted and linked by {@link AccountSecurityProfileChain}
     */
    public AccountSecurityProfileResolver(AccountSecurityProfileChain chain) {
        this.chain = chain;
    }

    /**
     * Normalizes threshold and share fields according to the user's configured security mode.
     *
     * @param user account DTO to validate and update in place
     */
    public void normalize(UserDTO user) {
        chain.normalize(new AccountSecurityProfileContext(user));
    }
}
