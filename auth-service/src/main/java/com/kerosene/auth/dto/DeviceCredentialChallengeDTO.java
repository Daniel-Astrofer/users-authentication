package com.kerosene.auth.dto;

/**
 * Typed step-up challenge for a single device-credential factor.
 * @param kind factor kind, currently PASSKEY or DEVICE_KEY
 * @param challengeId one-time device-key challenge identifier when kind is DEVICE_KEY
 * @param challenge challenge bytes represented using the selected protocol's encoding
 * @param expiresInSeconds remaining challenge lifetime
 * @param onionServiceId onion service identity bound into device-key canonical payloads
 * @param algorithm signature algorithm required by the device-key credential
 * @param canonicalization payload canonicalization version for device-key signatures
 * {@code DEVICE_KEY} uses challengeId + KEROSENE_JSON_V1 fields;
 * {@code PASSKEY} uses WebAuthn-shaped hex challenge (legacy / clearnet path).
 */
public record DeviceCredentialChallengeDTO(
        String kind,
        String challengeId,
        String challenge,
        Long expiresInSeconds,
        String onionServiceId,
        String algorithm,
        String canonicalization) {

    /** Creates a legacy passkey challenge using its hexadecimal WebAuthn-style challenge representation.
     * @param challengeHex hexadecimal passkey challenge
     * @param expiresInSeconds remaining lifetime
     * @return challenge DTO tagged as PASSKEY
     */
    public static DeviceCredentialChallengeDTO passkey(String challengeHex, long expiresInSeconds) {
        return new DeviceCredentialChallengeDTO(
                "PASSKEY",
                null,
                challengeHex,
                expiresInSeconds,
                null,
                null,
                null);
    }

    /** Creates a device-key challenge with the canonicalization and signature contract needed by the client.
     * @param challengeId opaque one-time challenge identifier
     * @param challenge encoded challenge bytes
     * @param expiresInSeconds remaining lifetime
     * @param onionServiceId onion identity bound into the signed payload
     * @param algorithm required signature algorithm
     * @param canonicalization canonical payload format identifier
     * @return challenge DTO tagged as DEVICE_KEY
     */
    public static DeviceCredentialChallengeDTO deviceKey(
            String challengeId,
            String challenge,
            long expiresInSeconds,
            String onionServiceId,
            String algorithm,
            String canonicalization) {
        return new DeviceCredentialChallengeDTO(
                "DEVICE_KEY",
                challengeId,
                challenge,
                expiresInSeconds,
                onionServiceId,
                algorithm,
                canonicalization);
    }
}
