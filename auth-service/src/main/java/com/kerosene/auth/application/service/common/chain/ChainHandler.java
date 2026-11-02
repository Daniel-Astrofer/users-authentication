package com.kerosene.auth.application.service.common.chain;

/**
 * One step in a chain where a handler may process or delegate a shared context.
 *
 * @param <T> context type
 */
public interface ChainHandler<T> {

    /**
     * Sets the next step in execution order; a null successor represents the end of the chain.
     *
     * @param next following handler, or null for the terminal step
     */
    void setNext(ChainHandler<T> next);

    /**
     * Processes the supplied context according to this step's responsibility.
     *
     * @param context mutable or immutable operation state shared with this chain step
     */
    void handle(T context);
}
