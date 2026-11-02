package com.kerosene.auth.application.service.security.profile;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.stereotype.Component;

/** Builds and executes the ordered chain that validates and normalizes account security settings. */
@Component
public class AccountSecurityProfileChain {

    /** Entry point of the sorted handler chain, or null when Spring discovers no handlers. */
    private final AccountSecurityProfileHandler firstHandler;

    /**
     * Sorts available handlers by Spring order and links them into a single forward chain.
     *
     * @param handlers all account security profile handlers discovered by Spring
     */
    public AccountSecurityProfileChain(List<AccountSecurityProfileHandler> handlers) {
        List<AccountSecurityProfileHandler> orderedHandlers = new ArrayList<>(handlers);
        AnnotationAwareOrderComparator.sort(orderedHandlers);
        this.firstHandler = linkHandlers(orderedHandlers);
    }

    /**
     * Runs profile validation and normalization from the first ordered handler; an empty chain is a no-op.
     *
     * @param context user DTO and resolved security mode to process
     */
    public void normalize(AccountSecurityProfileContext context) {
        if (firstHandler != null) {
            firstHandler.handle(context);
        }
    }

    /**
     * Links adjacent handlers while preserving the supplied order.
     *
     * @param handlers handlers already sorted by their declared order
     * @return first handler, or null for an empty list
     */
    private AccountSecurityProfileHandler linkHandlers(List<AccountSecurityProfileHandler> handlers) {
        for (int i = 0; i < handlers.size() - 1; i++) {
            handlers.get(i).setNext(handlers.get(i + 1));
        }
        return handlers.isEmpty() ? null : handlers.get(0);
    }
}
