package com.kerosene.platform.config.websocket.inbound;

import java.util.Optional;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;

/** Resolves an authentication token from one supported representation of STOMP headers. */
public interface StompTokenResolver {

    /**
     * Attempts token extraction from the supplied accessor.
     *
     * @param accessor parsed STOMP headers for the current frame
     * @return token when this resolver recognizes a supported header, otherwise empty
     */
    Optional<String> resolve(StompHeaderAccessor accessor);
}
