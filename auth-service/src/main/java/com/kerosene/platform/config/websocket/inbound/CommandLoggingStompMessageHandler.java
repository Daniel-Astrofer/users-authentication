package com.kerosene.platform.config.websocket.inbound;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.Message;

/** Logs STOMP command, session, and principal identifiers before forwarding the message. */
public class CommandLoggingStompMessageHandler extends AbstractStompMessageHandler {

    private static final Logger log = LoggerFactory.getLogger(CommandLoggingStompMessageHandler.class);

    /**
     * Creates the logging node and connects it to the rest of the message pipeline.
     *
     * @param next next handler in the inbound message pipeline
     */
    public CommandLoggingStompMessageHandler(StompMessageHandler next) {
        super(next);
    }

    /**
     * Logs command, session, and principal metadata when a command exists, then forwards the context.
     * Payload and authentication token contents are not written by this handler.
     *
     * @param context inbound STOMP frame with parsed accessor and command
     * @return message returned by the next chain node or the original message at the chain end
     */
    @Override
    public Message<?> handle(StompMessageContext context) {
        if (context.command() != null) {
            log.debug("[STOMP-IN] {} | Session: {} | User: {}",
                    context.command(),
                    context.accessor().getSessionId(),
                    context.accessor().getUser() != null ? context.accessor().getUser().getName() : "UNAUTHENTICATED");
        }
        return passToNext(context);
    }
}
