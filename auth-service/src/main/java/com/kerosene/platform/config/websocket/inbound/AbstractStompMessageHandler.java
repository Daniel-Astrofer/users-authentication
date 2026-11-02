package com.kerosene.platform.config.websocket.inbound;

import org.springframework.messaging.Message;

/** Base chain node for inbound STOMP message validation, logging, or transformation steps. */
public abstract class AbstractStompMessageHandler implements StompMessageHandler {

    private final StompMessageHandler next;

    /**
     * Creates a chain node with an optional successor.
     *
     * @param next next handler to receive an unhandled message, or null for the terminal node
     */
    protected AbstractStompMessageHandler(StompMessageHandler next) {
        this.next = next;
    }

    /**
     * Forwards the original message when this is the last handler, otherwise delegates the context.
     *
     * @param context current STOMP message and its parsed command/header state
     * @return message returned by the next handler, or the original message for a terminal node
     */
    protected Message<?> passToNext(StompMessageContext context) {
        if (next == null) {
            return context.message();
        }
        return next.handle(context);
    }
}
