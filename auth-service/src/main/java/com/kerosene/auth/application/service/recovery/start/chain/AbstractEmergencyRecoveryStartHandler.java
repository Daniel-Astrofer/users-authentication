package com.kerosene.auth.application.service.recovery.start.chain;

import com.kerosene.auth.application.service.common.chain.AbstractChainHandler;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;

/** Shared next-handler wiring for recovery initiation checks. */
public abstract class AbstractEmergencyRecoveryStartHandler extends AbstractChainHandler<EmergencyRecoveryStartContext>
        implements EmergencyRecoveryStartHandler {

    /** Creates a recovery validation step whose successor is assigned during chain assembly. */
    protected AbstractEmergencyRecoveryStartHandler() {
    }
}
