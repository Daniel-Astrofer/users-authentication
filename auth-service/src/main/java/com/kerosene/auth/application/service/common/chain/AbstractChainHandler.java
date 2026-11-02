package com.kerosene.auth.application.service.common.chain;

/**
 * Base for ordered handlers that may delegate an unchanged context to one successor.
 *
 * @param <T> context type passed through the chain
 */
public abstract class AbstractChainHandler<T> implements ChainHandler<T> {

    private ChainHandler<T> next;

    /** Creates an unlinked handler; chain assembly sets the successor before processing begins. */
    protected AbstractChainHandler() {
    }

    /**
     * Replaces the successor; passing {@code null} makes this handler the end of the chain.
     *
     * @param next handler to invoke after this step, or null when terminal
     */
    @Override
    public final void setNext(ChainHandler<T> next) {
        this.next = next;
    }

    /**
     * Delegates to the configured successor, doing nothing when this is the final handler.
     *
     * @param context operation state passed unchanged to the next handler
     */
    protected final void handleNext(T context) {
        if (next != null) {
            next.handle(context);
        }
    }
}
