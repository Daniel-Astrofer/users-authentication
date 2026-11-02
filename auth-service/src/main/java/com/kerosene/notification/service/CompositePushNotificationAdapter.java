package com.kerosene.notification.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Always logs push intent; optionally fans out via webhook when configured.
 *
 * <p>Resolves the circular "which PushNotificationPort is primary" problem:
 * this bean is {@link Primary}; logging is internal; webhook is optional.
 */
@Component
@Primary
public class CompositePushNotificationAdapter implements PushNotificationPort {

    /** Logger for optional adapter failures that are isolated from notification persistence. */
    private static final Logger logger = LoggerFactory.getLogger(CompositePushNotificationAdapter.class);

    private final LoggingPushNotificationAdapter loggingAdapter;
    private final ObjectProvider<WebhookPushNotificationAdapter> webhookAdapter;

    /** Creates the composite fan-out with a required logger and optional webhook adapter.
     * @param loggingAdapter local logging implementation
     * @param webhookAdapter provider for the configured webhook adapter, when present
     */
    public CompositePushNotificationAdapter(
            LoggingPushNotificationAdapter loggingAdapter,
            ObjectProvider<WebhookPushNotificationAdapter> webhookAdapter) {
        this.loggingAdapter = loggingAdapter;
        this.webhookAdapter = webhookAdapter;
    }

    @Override
    /** Attempts local logging and optional webhook delivery independently.
     * @param userId notification recipient
     * @param payload notification fields to dispatch
     */
    public void dispatch(Long userId, Map<String, Object> payload) {
        try {
            loggingAdapter.dispatch(userId, payload);
        } catch (Exception exception) {
            logger.warn("Logging push adapter failed: {}", exception.getMessage());
        }

        WebhookPushNotificationAdapter webhook = webhookAdapter.getIfAvailable();
        if (webhook == null) {
            return;
        }
        try {
            webhook.dispatch(userId, payload);
        } catch (Exception exception) {
            logger.warn("Webhook push adapter failed: {}", exception.getMessage());
        }
    }
}
