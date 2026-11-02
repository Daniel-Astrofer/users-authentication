package com.kerosene.platform.market;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Broadcasts BTC market quotes to all authenticated STOMP sessions.
 *
 * <p>Destination: {@code /topic/btc-price}. Payload matches
 * {@code GET /api/economy/btc-price} data map.
 */
@Service
public class BtcPriceEventPublisher {

    /** Logger for websocket publication outcomes. */
    private static final Logger log = LoggerFactory.getLogger(BtcPriceEventPublisher.class);

    /** STOMP topic receiving the public BTC quote map. */
    public static final String DESTINATION = "/topic/btc-price";

    private final SimpMessagingTemplate messagingTemplate;

    /** Creates the publisher with an optional websocket transport.
     * @param messagingTemplate provider that may be empty when messaging is disabled
     */
    public BtcPriceEventPublisher(ObjectProvider<SimpMessagingTemplate> messagingTemplate) {
        this.messagingTemplate = messagingTemplate.getIfAvailable();
    }

    /** Broadcasts a nonempty quote and logs transport failures without disrupting price retrieval.
     * @param quote quote fields shared with the HTTP economy endpoint
     */
    public void publish(Map<String, Object> quote) {
        if (messagingTemplate == null || quote == null || quote.isEmpty()) {
            return;
        }
        try {
            messagingTemplate.convertAndSend(DESTINATION, quote);
            log.info(
                    "[WS] Published BTC price to {} usd={} brl={}",
                    DESTINATION,
                    quote.get("btcUsd"),
                    quote.get("btcBrl"));
        } catch (Exception e) {
            log.error("Failed to publish BTC price websocket event", e);
        }
    }
}
