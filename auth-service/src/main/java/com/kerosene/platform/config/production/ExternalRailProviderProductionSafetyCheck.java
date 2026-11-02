package com.kerosene.platform.config.production;

import com.kerosene.common.financial.operations.FinancialRailProductionSafetyPort;

/** Adds production-readiness violations reported by the configured financial rail integration. */
public class ExternalRailProviderProductionSafetyCheck extends AbstractProductionSafetyCheck {

    /** Creates this safety-check stage in the production validation chain.
     * @param next next safety check to run after this stage
     */
    public ExternalRailProviderProductionSafetyCheck(ProductionSafetyCheck next) {
        super(next);
    }

    @Override
    /** Requires the rail safety port and accumulates its production configuration findings.
     * @param context Spring environment and violation collector for this startup validation
     */
    protected void inspect(ProductionSafetyContext context) {
        FinancialRailProductionSafetyPort safetyPort = context.beanFactory()
                .getBeanProvider(FinancialRailProductionSafetyPort.class)
                .getIfAvailable();
        if (safetyPort == null) {
            context.addViolation("Financial rail production safety port must be available in prod");
            return;
        }
        safetyPort.collectProductionViolations().forEach(context::addViolation);
    }
}
