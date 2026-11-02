package com.kerosene.platform.config.websocket.inbound;

import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageDeliveryException;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;

/** Authenticates STOMP CONNECT frames with the JWT from a native header. */
public class ConnectAuthenticationStompMessageHandler extends AbstractStompMessageHandler {

    /** Logger for rejected and accepted websocket connection attempts. */
    private static final Logger log = LoggerFactory.getLogger(ConnectAuthenticationStompMessageHandler.class);

    private final JwtServicer jwtServicer;
    private final StompTokenResolver tokenResolver;
    private final com.kerosene.platform.config.websocket.StompSessionAuthorization sessions;

    /** Creates the authentication stage in the inbound STOMP handler chain.
     * @param jwtServicer validates and extracts the user identity from JWTs
     * @param tokenResolver reads a token from STOMP native headers
     * @param next next handler in the inbound chain
     */
    public ConnectAuthenticationStompMessageHandler(
            JwtServicer jwtServicer,
            StompTokenResolver tokenResolver,
            com.kerosene.platform.config.websocket.StompSessionAuthorization sessions,
            StompMessageHandler next) {
        super(next);
        this.jwtServicer = jwtServicer;
        this.tokenResolver = tokenResolver;
        this.sessions = sessions;
    }

    @Override
    /** Authenticates CONNECT frames and passes other commands to the next handler.
     * @param context parsed command, accessor, and message context
     * @return result from the next handler after successful authentication
     * @throws MessageDeliveryException when a CONNECT frame has no valid JWT
     */
    public Message<?> handle(StompMessageContext context) {
        if (!StompCommand.CONNECT.equals(context.command())) {
            return passToNext(context);
        }

        String token = tokenResolver.resolve(context.accessor())
                .orElseThrow(() -> {
                    log.warn("[STOMP-AUTH] CONNECT rejected: missing Authorization native header. Session: {}",
                            context.accessor().getSessionId());
                    return new MessageDeliveryException("Unauthorized: JWT token is required to connect.");
                });

        try {
            if (jwtServicer.isSessionRevoked(token)) throw new IllegalStateException("Session is revoked.");
            Long userId = jwtServicer.extractId(token);
            sessions.register(context.accessor().getSessionId(), token);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userId.toString(),
                    null,
                    Collections.emptyList());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            context.accessor().setUser(authentication);
            log.debug("[STOMP-AUTH] CONNECT authenticated for user: {}", userId);
        } catch (Exception exception) {
            log.warn("[STOMP-AUTH] CONNECT rejected: invalid JWT. Session: {}. Reason: {}",
                    context.accessor().getSessionId(),
                    exception.getMessage());
            throw new MessageDeliveryException(
                    "Unauthorized: Invalid or expired JWT token. Connection refused.");
        }

        return passToNext(context);
    }
}
