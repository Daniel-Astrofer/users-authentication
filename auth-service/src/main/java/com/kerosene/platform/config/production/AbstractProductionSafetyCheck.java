package com.kerosene.platform.config.production;

/** Base chain node that performs one production safety inspection before invoking its successor. */
public abstract class AbstractProductionSafetyCheck implements ProductionSafetyCheck {

    private final ProductionSafetyCheck next;

    /**
     * Creates one safety check node.
     *
     * @param next next safety check, or null when this node terminates the chain
     */
    protected AbstractProductionSafetyCheck(ProductionSafetyCheck next) {
        this.next = next;
    }

    /** Runs this check and then every configured successor in order. */
    @Override
    public final void handle(ProductionSafetyContext context) {
        inspect(context);
        if (next != null) {
            next.handle(context);
        }
    }

    /**
     * Performs this node's validation and records or raises failures through the supplied context.
     *
     * @param context startup configuration values and validation result sink
     */
    protected abstract void inspect(ProductionSafetyContext context);
}
