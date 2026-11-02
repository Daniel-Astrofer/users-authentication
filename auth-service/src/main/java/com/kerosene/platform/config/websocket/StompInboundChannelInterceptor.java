package com.kerosene.platform.config.websocket;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.stereotype.Component;
import com.kerosene.platform.config.websocket.inbound.StompInboundMessageHandlerChain;
import com.kerosene.platform.config.websocket.inbound.StompMessageContext;

@Component
public class StompInboundChannelInterceptor implements ChannelInterceptor {

    private final StompInboundMessageHandlerChain handlerChain;
    private final StompSessionAuthorization sessions;

    public StompInboundChannelInterceptor(StompInboundMessageHandlerChain handlerChain, StompSessionAuthorization sessions) {
        this.handlerChain = handlerChain;
        this.sessions = sessions;
    }

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
        if (accessor == null) {
            return message;
        }
        var command = accessor.getCommand();
        if (command == org.springframework.messaging.simp.stomp.StompCommand.DISCONNECT) {
            sessions.remove(accessor.getSessionId());
        } else if (command != null && command != org.springframework.messaging.simp.stomp.StompCommand.CONNECT
                && !sessions.isAuthorized(accessor.getSessionId())) {
            throw new org.springframework.messaging.MessageDeliveryException("Session is no longer authorized.");
        }
        return handlerChain.handle(new StompMessageContext(message, accessor));
    }
}
