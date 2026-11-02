package com.kerosene.platform.config.websocket;

import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.MessageDeliveryException;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.SessionDisconnectEvent;
import java.util.concurrent.ConcurrentHashMap;

/** Rechecks revocation for established connections before private frames can cross the channel. */
@Component
public class StompSessionAuthorization {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StompSessionAuthorization.class);
    private final JwtServicer jwt;
    private final ConcurrentHashMap<String, String> tokens = new ConcurrentHashMap<>();
    public StompSessionAuthorization(JwtServicer jwt) { this.jwt = jwt; }

    public void register(String sessionId, String token) {
        if (sessionId == null || sessionId.isBlank() || tokens.putIfAbsent(sessionId, token) != null) {
            throw new MessageDeliveryException("Connection cannot be authenticated again.");
        }
    }

    public boolean isAuthorized(String sessionId) {
        String token = sessionId == null ? null : tokens.get(sessionId);
        if (token == null) return false;
        try { return !jwt.isSessionRevoked(token); }
        catch (io.jsonwebtoken.ExpiredJwtException expired) { return false; }
        catch (RuntimeException unavailable) {
            log.warn("STOMP authorization check failed; private frame denied ({})", unavailable.getClass().getSimpleName());
            return false;
        }
    }

    public void remove(String sessionId) { if (sessionId != null) tokens.remove(sessionId); }

    @EventListener
    public void disconnected(SessionDisconnectEvent event) { remove(event.getSessionId()); }
}
