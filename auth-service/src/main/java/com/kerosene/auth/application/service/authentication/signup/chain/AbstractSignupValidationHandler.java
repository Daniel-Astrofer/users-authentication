package com.kerosene.auth.application.service.authentication.signup.chain;

import com.kerosene.auth.application.service.authentication.signup.SignupValidationContext;
import com.kerosene.auth.application.service.common.chain.AbstractChainHandler;

/** Shared chain-link implementation for signup validation steps. */
public abstract class AbstractSignupValidationHandler extends AbstractChainHandler<SignupValidationContext>
        implements SignupValidationHandler {

    /** Creates a signup validation step whose successor is assigned during chain assembly. */
    protected AbstractSignupValidationHandler() {
    }
}
