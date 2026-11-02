package com.kerosene.notification.dto;

/** Client input used to register a remote-push token for a notification device.
 * @param platform client platform or push-provider family
 * @param token opaque push token supplied by the platform
 * @param deviceId client device identifier used for device-level registration
 * @param appVersion client application version reported with the token
 */
public record DeviceTokenRegisterRequest(
        String platform,
        String token,
        String deviceId,
        String appVersion) {
}
