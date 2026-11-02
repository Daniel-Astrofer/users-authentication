package com.kerosene.security.application.honeypot.handler;

import com.kerosene.security.application.honeypot.HoneypotInspectionContext;
import com.kerosene.security.domain.honeypot.HoneypotInspectionResult;

import java.util.Optional;

/** Skips body inspection for requests without a body and forwards them to the next processing stage. */
public class EmptyBodyInspectionHandler extends AbstractHoneypotInspectionHandler {

    /** Creates the empty-body check in the ordered honeypot inspection chain.
     * @param next following inspection handler
     */
    public EmptyBodyInspectionHandler(HoneypotInspectionHandler next) {
        super(next);
    }

    @Override
    /** Returns a forward result for empty bodies, or lets the next handler inspect nonempty requests.
     * @param context request metadata and cached body state
     * @return inspection result when this handler applies, otherwise empty
     */
    protected Optional<HoneypotInspectionResult> tryHandle(HoneypotInspectionContext context) {
        if (!context.hasBody()) {
            return Optional.of(HoneypotInspectionResult.forward());
        }
        return Optional.empty();
    }
}
