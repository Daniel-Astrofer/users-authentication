package com.kerosene.security.application.honeypot.handler;

import com.kerosene.security.application.honeypot.HoneypotInspectionContext;
import com.kerosene.security.domain.honeypot.HoneypotInspectionResult;

/** Contract for a component that inspects a request and produces a honeypot disposition. */
public interface HoneypotInspectionHandler {

    /**
     * Evaluates this inspection step for the supplied request.
     *
     * @param context request attributes and signals used by honeypot rules
     * @return resulting disposition
     */
    HoneypotInspectionResult handle(HoneypotInspectionContext context);
}
