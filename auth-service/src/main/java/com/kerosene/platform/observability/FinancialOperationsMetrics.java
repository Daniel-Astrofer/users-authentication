package com.kerosene.platform.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/** Records outcome counters for financial operations using bounded outcome and type tags. */
@Component
public class FinancialOperationsMetrics {

    /** Micrometer registry receiving financial operation counters. */
    private final MeterRegistry meterRegistry;

    /** Creates the metrics adapter with the application's shared registry.
     * @param meterRegistry registry used to create or reuse counters
     */
    public FinancialOperationsMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    /** Increments an operation counter tagged by its outcome.
     * @param name operation-specific metric suffix
     * @param outcome normalized result label
     */
    public void increment(String name, String outcome) {
        Counter.builder("kerosene.financial." + name)
                .tag("outcome", outcome)
                .register(meterRegistry)
                .increment();
    }

    /** Increments an operation counter tagged by outcome and operation type.
     * @param name operation-specific metric suffix
     * @param outcome normalized result label
     * @param type operation category, defaulted to {@code unknown} when null
     */
    public void increment(String name, String outcome, String type) {
        Counter.builder("kerosene.financial." + name)
                .tag("outcome", outcome)
                .tag("type", type != null ? type : "unknown")
                .register(meterRegistry)
                .increment();
    }
}
