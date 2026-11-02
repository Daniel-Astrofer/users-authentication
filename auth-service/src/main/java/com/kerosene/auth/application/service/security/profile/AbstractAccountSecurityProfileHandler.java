package com.kerosene.auth.application.service.security.profile;

import com.kerosene.auth.application.service.common.chain.AbstractChainHandler;

/** Shared chain-of-responsibility base that delegates account profile normalization to typed handlers. */
public abstract class AbstractAccountSecurityProfileHandler extends AbstractChainHandler<AccountSecurityProfileContext>
        implements AccountSecurityProfileHandler {

    /** Creates a profile handler whose successor is assigned during chain assembly. */
    protected AbstractAccountSecurityProfileHandler() {
    }
}
