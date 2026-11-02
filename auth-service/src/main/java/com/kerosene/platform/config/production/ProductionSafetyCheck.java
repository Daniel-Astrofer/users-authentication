package com.kerosene.platform.config.production;

/** One startup validation step for configuration required to run safely in production. */
public interface ProductionSafetyCheck {

    /**
     * Evaluates this check and its successors; implementations fail startup for unsafe configuration.
     *
     * @param context configuration and accumulated validation details for startup
     */
    void handle(ProductionSafetyContext context);
}
