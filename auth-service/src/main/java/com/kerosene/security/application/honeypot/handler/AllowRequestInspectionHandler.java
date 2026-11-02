package com.kerosene.security.application.honeypot.handler;

import com.kerosene.security.application.honeypot.HoneypotInspectionContext;
import com.kerosene.security.domain.honeypot.HoneypotInspectionResult;

import java.util.Optional;

/** Terminal honeypot rule that forwards requests when no earlier inspection rule rejects them. */
public class AllowRequestInspectionHandler extends AbstractHoneypotInspectionHandler {

    /** Creates the terminal allow rule with no successor. */
    public AllowRequestInspectionHandler() {
        super(null);
    }

    /**
     * Produces a forward decision unconditionally as the final fallback in the inspection chain.
     *
     * @param context inspected request context; this fallback does not add another rule
     * @return an explicit forward decision
     */
    @Override
    protected Optional<HoneypotInspectionResult> tryHandle(HoneypotInspectionContext context) {
        return Optional.of(HoneypotInspectionResult.forward());
    }
}
