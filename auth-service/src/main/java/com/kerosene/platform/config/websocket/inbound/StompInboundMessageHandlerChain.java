package com.kerosene.platform.config.websocket.inbound;

import org.springframework.messaging.Message;
import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;

@Component
public class StompInboundMessageHandlerChain implements StompMessageHandler {

    private final StompMessageHandler chain;

    public StompInboundMessageHandlerChain(JwtServicer jwtServicer,
            com.kerosene.platform.config.websocket.StompSessionAuthorization sessions) {
        StompTokenResolver tokenResolver = new NativeHeaderStompTokenResolver(null);

        this.chain = new ConnectAuthenticationStompMessageHandler(
                jwtServicer,
                tokenResolver,
                sessions,
                new SubscribeAuthorizationStompMessageHandler(
                        new CommandLoggingStompMessageHandler(null)));
    }

    @Override
    public Message<?> handle(StompMessageContext context) {
        return chain.handle(context);
    }
}
