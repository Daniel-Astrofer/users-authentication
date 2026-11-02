package com.kerosene.notification.service;

import java.util.Map;

/**
 * Optional remote push channel (FCM / APNs / vendor webhook).
 *
 * <p>Default implementation is logging-only: Kerosene is Tor-first and currently
 * delivers via STOMP + on-device background poll. Plug a real adapter when
 * product enables remote push without violating custody/privacy constraints.
 */
public interface PushNotificationPort {

    /** Best-effort fan-out to the user's registered device tokens; implementations must not break notification persistence.
     * @param userId owner of the target device tokens
     * @param payload notification fields to deliver
     */
    void dispatch(Long userId, Map<String, Object> payload);
}
