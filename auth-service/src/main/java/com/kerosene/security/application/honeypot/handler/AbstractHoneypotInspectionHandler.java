package com.kerosene.security.application.honeypot.handler;

import com.kerosene.security.application.honeypot.HoneypotInspectionContext;
import com.kerosene.security.domain.honeypot.HoneypotInspectionResult;

import java.util.Optional;

/**
 * Chain step that returns its own honeypot decision or delegates inspection to the next step.
 * A chain with no matching decision and no successor defaults to forwarding the request.
 */
public abstract class AbstractHoneypotInspectionHandler implements HoneypotInspectionHandler {

    private final HoneypotInspectionHandler next;

    /**
     * Creates a chain step with an optional successor.
     *
     * @param next following inspection step, or null for the final step
     */
    protected AbstractHoneypotInspectionHandler(HoneypotInspectionHandler next) {
        this.next = next;
    }

    /** Returns this step's decision, the successor's decision, or the default forward decision. */
    @Override
    public final HoneypotInspectionResult handle(HoneypotInspectionContext context) {
        Optional<HoneypotInspectionResult> currentDecision = tryHandle(context);
        if (currentDecision.isPresent()) {
            return currentDecision.get();
        }
        if (next == null) {
            return HoneypotInspectionResult.forward();
        }
        return next.handle(context);
    }

    /**
     * Evaluates only this handler's rule; empty means the next step may inspect the context.
     *
     * @param context request features evaluated by this rule
     * @return decision when this handler matches, or empty to delegate
     */
    protected abstract Optional<HoneypotInspectionResult> tryHandle(HoneypotInspectionContext context);
}
