package com.kerosene.notification.dto;

import com.kerosene.notification.model.entity.NotificationDeviceTokenEntity;

import java.time.LocalDateTime;

/** Safe API projection of a registered push token and its lifecycle timestamps.
 * @param id persistent token registration identifier
 * @param platform push provider or client platform
 * @param tokenRef nonsecret reference for the stored token
 * @param deviceRef nonsecret reference for the registering device
 * @param appVersion application version reported during registration
 * @param createdAt token registration time
 * @param lastSeenAt latest observed use time
 * @param revokedAt revocation time, or null while active
 * @param active whether this token remains eligible for delivery
 */
public record DeviceTokenResponse(
        Long id,
        String platform,
        String tokenRef,
        String deviceRef,
        String appVersion,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt,
        LocalDateTime revokedAt,
        boolean active) {

    /** Projects a persisted token without exposing the raw push token.
     * @param entity persisted notification token
     * @return safe response projection with activity derived from revocation state
     */
    public static DeviceTokenResponse from(NotificationDeviceTokenEntity entity) {
        return new DeviceTokenResponse(
                entity.getId(),
                entity.getPlatform(),
                entity.getTokenRef(),
                entity.getDeviceRef(),
                entity.getAppVersion(),
                entity.getCreatedAt(),
                entity.getLastSeenAt(),
                entity.getRevokedAt(),
                entity.getRevokedAt() == null);
    }
}
