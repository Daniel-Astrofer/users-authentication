package com.kerosene.platform.config.websocket.inbound;

import java.util.Optional;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;

/** Base chain node for extracting an authentication token from supported STOMP header locations. */
public abstract class AbstractStompTokenResolver implements StompTokenResolver {

    private final StompTokenResolver next;

    /**
     * Creates a resolver node with an optional token source to consult next.
     *
     * @param next next token source to consult when this resolver cannot produce a token
     */
    protected AbstractStompTokenResolver(StompTokenResolver next) {
        this.next = next;
    }

    /**
     * Delegates token lookup or returns empty when no resolver follows this one.
     *
     * @param accessor parsed STOMP headers for the current connection or message
     * @return token resolved by a successor, or empty for the terminal node
     */
    protected Optional<String> resolveNext(StompHeaderAccessor accessor) {
        if (next == null) {
            return Optional.empty();
        }
        return next.resolve(accessor);
    }
}
