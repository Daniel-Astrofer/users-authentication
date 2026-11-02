package com.kerosene.auth.dto.devicekey;

import com.kerosene.auth.model.entity.DeviceKeyCredential;

import java.time.LocalDateTime;

/**
 * Safe client projection of a registered device credential and its lifecycle metadata.
 * @param credentialId stable credential identifier
 * @param deviceName user-assigned device label
 * @param deviceInstallId installation identity used for device-scoped management
 * @param keyStorage declared hardware or software key storage class
 * @param platform operating system or platform family
 * @param browser client browser when provided
 * @param onionServiceId onion service identity associated with registration
 * @param status credential lifecycle status
 * @param counter last accepted anti-replay counter
 * @param createdAt credential creation time
 * @param lastUsedAt most recent successful verification time
 * @param revokedAt revocation time, or null while active
 * @param protocolVersion payload protocol used by this credential
 */
public record DeviceKeyDeviceDTO(
        String credentialId,
        String deviceName,
        String deviceInstallId,
        String keyStorage,
        String platform,
        String browser,
        String onionServiceId,
        String status,
        long counter,
        LocalDateTime createdAt,
        LocalDateTime lastUsedAt,
        LocalDateTime revokedAt,
        int protocolVersion) {

    /** Projects persisted credential metadata into the public device listing without exposing key bytes.
     * @param credential persisted credential entity
     * @return public device DTO containing identity, status, timestamps, and replay counter
     */
    public static DeviceKeyDeviceDTO from(DeviceKeyCredential credential) {
        return new DeviceKeyDeviceDTO(
                credential.getCredentialId(),
                credential.getDeviceName(),
                credential.getDeviceInstallId(),
                credential.getKeyStorage(),
                credential.getPlatform(),
                credential.getBrowser(),
                credential.getOnionServiceId(),
                credential.getStatus(),
                credential.getCounter(),
                credential.getCreatedAt(),
                credential.getLastUsedAt(),
                credential.getRevokedAt(),
                credential.getProtocolVersion());
    }
}
