package com.kerosene.auth.application.service.recovery.start.chain;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.stereotype.Component;

import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;

/** Builds and runs the ordered proof-validation chain for emergency-recovery initiation. */
@Component
public class EmergencyRecoveryStartChain {

    /** First request-validation handler, or null if no handlers are configured. */
    private final EmergencyRecoveryStartHandler firstHandler;

    /**
     * Sorts recovery handlers by order and links them into a single sequence.
     * @param handlers Spring-provided recovery start handlers
     */
    public EmergencyRecoveryStartChain(List<EmergencyRecoveryStartHandler> handlers) {
        List<EmergencyRecoveryStartHandler> orderedHandlers = new ArrayList<>(handlers);
        AnnotationAwareOrderComparator.sort(orderedHandlers);
        this.firstHandler = linkHandlers(orderedHandlers);
    }

    /**
     * Creates a context, executes the configured proof chain, and returns validated recovery data.
     * @param request submitted recovery proof request
     * @param clientFingerprint abuse-control client reference
     * @return populated recovery context
     */
    public EmergencyRecoveryStartContext handle(EmergencyRecoveryStartRequest request, String clientFingerprint) {
        EmergencyRecoveryStartContext context = new EmergencyRecoveryStartContext(request, clientFingerprint);
        if (firstHandler != null) {
            firstHandler.handle(context);
        }
        return context;
    }

    /**
     * Links adjacent ordered handlers and returns the first step.
     * @param handlers handlers already sorted by Spring order
     * @return first handler, or null for an empty list
     */
    private EmergencyRecoveryStartHandler linkHandlers(List<EmergencyRecoveryStartHandler> handlers) {
        for (int i = 0; i < handlers.size() - 1; i++) {
            handlers.get(i).setNext(handlers.get(i + 1));
        }
        return handlers.isEmpty() ? null : handlers.get(0);
    }
}
