package com.kerosene.platform.config.websocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.stereotype.Component;

@Component
public class StompOutboundChannelInterceptor implements ChannelInterceptor {

    private final StompSessionAuthorization sessions;
    public StompOutboundChannelInterceptor(StompSessionAuthorization sessions) { this.sessions = sessions; }

    private static final Logger log = LoggerFactory.getLogger(StompOutboundChannelInterceptor.class);

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        // Broker messages often use SimpMessageHeaderAccessor, not a STOMP accessor.
        if (org.springframework.messaging.simp.SimpMessageHeaderAccessor.getMessageType(message.getHeaders())
                == org.springframework.messaging.simp.SimpMessageType.MESSAGE
                && !sessions.isAuthorized(org.springframework.messaging.simp.SimpMessageHeaderAccessor.getSessionId(message.getHeaders()))) {
            return null;
        }
        StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
        if (accessor == null) {
            return message;
        }

        StompCommand command = accessor.getCommand();
        if (command == null) {
            return message;
        }

        if (StompCommand.ERROR.equals(command)) {
            log.warn("[STOMP-ERROR] {}", accessor.getMessage());
        } else if (StompCommand.CONNECTED.equals(command)) {
            log.debug("[STOMP-OUT] CONNECTED | Session: {}", accessor.getSessionId());
        }

        return message;
    }
}
