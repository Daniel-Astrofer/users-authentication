package com.kerosene.auth.application.service.devicekey;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Issues one-time device-key challenges and verifies canonical Ed25519 registration/authentication proofs. */
@Service
public class DeviceKeyService {

    /** Algorithm identifier included in device-key response and signed protocol data. */
    public static final String ALGORITHM = "Ed25519";
    /** Versioned deterministic JSON encoding required before signature verification. */
    public static final String CANONICALIZATION = "KEROSENE_JSON_V1";
    /** Signed operation type used when registering a device key. */
    public static final String REGISTER_TYPE = "REGISTER_DEVICE_KEY";
    /** Signed operation type used when authenticating with a device key. */
    public static final String AUTH_TYPE = "AUTH_DEVICE_KEY";

    /** Redis namespace separating device-key challenges from other challenge types. */
    private static final String CHALLENGE_PREFIX = "device_key_challenge:";
    /** X.509 SubjectPublicKeyInfo prefix for a raw Ed25519 public key. */
    private static final byte[] ED25519_X509_PREFIX = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    /** Jackson payload shape for simple string-keyed canonical JSON fields. */
    private static final TypeReference<LinkedHashMap<String, Object>> PAYLOAD_TYPE = new DeviceKeyPayloadType();

    /** Redis storage boundary for challenge TTL and atomic consumption. */
    private final RedisServicer redisService;
    /** Mapper for challenge state and signed request payloads. */
    private final ObjectMapper objectMapper;
    /** Cryptographically secure source for challenge IDs and challenge material. */
    private final SecureRandom secureRandom = new SecureRandom();
    /** Configured onion/RP identity included in challenge responses and signed payloads. */
    private final String onionServiceId;
    /** Expiration duration applied to challenge state, in seconds. */
    private final long challengeTtlSeconds;

    /** Creates the device-key service, applying fallback identity and positive challenge TTL defaults.
     * @param redisService Redis challenge storage
     * @param objectMapper JSON state/payload mapper
     * @param onionServiceId configured onion or RP identity
     * @param challengeTtlSeconds challenge validity interval
     */
    public DeviceKeyService(
            RedisServicer redisService,
            ObjectMapper objectMapper,
            @Value("${device-key.onion-service-id:${webauthn.relying-party-id:kerosene-device}}")
            String onionServiceId,
            @Value("${device-key.challenge-ttl-seconds:90}") long challengeTtlSeconds) {
        this.redisService = redisService;
        this.objectMapper = objectMapper;
        this.onionServiceId = normalizeRequired(onionServiceId, "kerosene-device");
        this.challengeTtlSeconds = challengeTtlSeconds > 0 ? challengeTtlSeconds : 90L;
    }

    /** Issues a registration challenge bound to the signup session and normalized username.
     * @param sessionId pending signup session
     * @param username pending account username
     * @return challenge ID/material, TTL, protocol identity, algorithm and canonicalization
     */
    public DeviceKeyChallengeResponse startRegistrationChallenge(String sessionId, String username) {
        return issueChallenge(
                DeviceKeyChallengePurpose.REGISTER_DEVICE_KEY,
                normalizeUsername(username),
                null,
                normalizeRequired(sessionId, ""));
    }

    /** Issues an authentication challenge bound to an existing user ID and normalized username.
     * @param user authenticated account
     * @return challenge response
     */
    public DeviceKeyChallengeResponse startAuthenticationChallenge(UserDataBase user) {
        return issueChallenge(
                DeviceKeyChallengePurpose.AUTH_DEVICE_KEY,
                normalizeUsername(user.getUsername()),
                user.getId(),
                null);
    }

    /** Issues an account-bound registration challenge for a user who is already authenticated.
     * @param user authenticated account
     * @return challenge response
     */
    public DeviceKeyChallengeResponse startAuthenticatedRegistrationChallenge(UserDataBase user) {
        return issueChallenge(
                DeviceKeyChallengePurpose.REGISTER_DEVICE_KEY,
                normalizeUsername(user.getUsername()),
                user.getId(),
                "");
    }

    /**
     * Validates registration fields, key fingerprint, challenge purpose/owner/session, canonical payload,
     * and Ed25519 signature before returning trusted registration metadata.
     *
     * @param request client registration proof and device metadata
     * @param expectedSessionId signup session expected by the caller; empty for authenticated registration
     * @param expectedUsername account username expected by the caller
     * @return verified credential material suitable for persistence
     */
    public VerifiedDeviceKeyRegistration verifyRegistration(
            DeviceKeyRegistrationRequest request,
            String expectedSessionId,
            String expectedUsername) {
        requireNonBlank(request.getCredentialId(), "credentialId is required.");
        requireNonBlank(request.getPublicKey(), "publicKey is required.");
        requireNonBlank(request.getDeviceInstallId(), "deviceInstallId is required.");

        byte[] publicKeyBytes = decodeBase64Flexible(request.getPublicKey(), "publicKey");
        String publicKeySha256 = base64Url(sha256(publicKeyBytes));
        if (request.getPublicKeySha256() != null && !request.getPublicKeySha256().isBlank()
                && !Objects.equals(publicKeySha256, request.getPublicKeySha256().trim())) {
            throw new DeviceKeyProtocolException("publicKeySha256 does not match publicKey.");
        }

        LinkedHashMap<String, Object> payload = parsePayload(request.getSignedPayload());
        long counter = longField(payload, "counter");
        long issuedAt = longField(payload, "issuedAtEpochSeconds");
        validateIssuedAt(issuedAt);

        DeviceKeyChallengeState challenge = consumeChallenge(stringField(payload, "challengeId"));
        if (challenge.purpose() != DeviceKeyChallengePurpose.REGISTER_DEVICE_KEY) {
            throw new DeviceKeyProtocolException("Challenge purpose does not allow device key registration.");
        }
        if (!Objects.equals(normalizeUsername(expectedUsername), normalizeUsername(challenge.username()))) {
            throw new DeviceKeyProtocolException("Challenge username mismatch.");
        }
        if (!Objects.equals(normalizeRequired(expectedSessionId, ""), normalizeRequired(challenge.sessionId(), ""))) {
            throw new DeviceKeyProtocolException("Challenge session mismatch.");
        }

        Map<String, Object> expectedPayload = registrationPayload(
                challenge,
                request.getCredentialId().trim(),
                request.getDeviceInstallId().trim(),
                publicKeySha256,
                counter,
                issuedAt);
        verifyCanonicalPayload(request.getSignedPayload(), expectedPayload);
        verifySignature(publicKeyBytes, request.getSignedPayload(), request.getSignature());

        return new VerifiedDeviceKeyRegistration(
                request.getCredentialId().trim(),
                firstNonBlank(request.getUserHandle(), request.getCredentialId()).trim(),
                request.getPublicKey().trim(),
                publicKeySha256,
                counter,
                firstNonBlank(request.getDeviceName(), "Dispositivo Kerosene"),
                request.getDeviceInstallId().trim(),
                firstNonBlank(request.getKeyStorage(), "SECURE_STORAGE"),
                firstNonBlank(request.getPlatform(), ""),
                firstNonBlank(request.getBrowser(), ""),
                firstNonBlank(request.getBrand(), ""),
                firstNonBlank(request.getModel(), ""),
                firstNonBlank(request.getSerialNumber(), ""),
                onionServiceId);
    }

    /** Verifies an active owner's device-key assertion and returns its strictly advancing counter.
     * @param request client assertion and signed canonical payload
     * @param user account selected by the caller
     * @param credential persisted key and current counter
     * @return verified counter that must still be advanced atomically in persistence
     * @throws DeviceKeyReplayException when the counter does not advance
     */
    public long verifyAuthentication(
            DeviceKeyVerifyRequest request,
            UserDataBase user,
            DeviceKeyCredential credential) {
        requireNonBlank(request.getCredentialId(), "credentialId is required.");
        requireNonBlank(request.getDeviceInstallId(), "deviceInstallId is required.");
        requireNonBlank(credential.getPublicKeyEd25519(), "Stored public key is missing.");

        if (!"ACTIVE".equalsIgnoreCase(credential.getStatus())) {
            throw new DeviceKeyProtocolException("Device key is not active.");
        }
        if (!Objects.equals(request.getDeviceInstallId().trim(), credential.getDeviceInstallId())) {
            throw new DeviceKeyProtocolException("deviceInstallId does not match credential.");
        }
        if (!ALGORITHM.equals(credential.getAlgorithm())) {
            throw new DeviceKeyProtocolException("Stored algorithm is not supported.");
        }

        LinkedHashMap<String, Object> payload = parsePayload(request.getSignedPayload());
        long counter = longField(payload, "counter");
        long issuedAt = longField(payload, "issuedAtEpochSeconds");
        validateIssuedAt(issuedAt);

        DeviceKeyChallengeState challenge = consumeChallenge(stringField(payload, "challengeId"));
        if (challenge.purpose() != DeviceKeyChallengePurpose.AUTH_DEVICE_KEY) {
            throw new DeviceKeyProtocolException("Challenge purpose does not allow authentication.");
        }
        if (!Objects.equals(user.getId(), challenge.userId())) {
            throw new DeviceKeyProtocolException("Challenge user mismatch.");
        }
        if (!Objects.equals(normalizeUsername(user.getUsername()), normalizeUsername(challenge.username()))) {
            throw new DeviceKeyProtocolException("Challenge username mismatch.");
        }
        if (counter <= credential.getCounter()) {
            throw new DeviceKeyReplayException("Device key counter did not advance.");
        }

        Map<String, Object> expectedPayload = authenticationPayload(
                challenge,
                user.getUsername(),
                credential.getCredentialId(),
                credential.getDeviceInstallId(),
                counter,
                issuedAt);
        verifyCanonicalPayload(request.getSignedPayload(), expectedPayload);
        verifySignature(
                decodeBase64Flexible(credential.getPublicKeyEd25519(), "stored public key"),
                request.getSignedPayload(),
                request.getSignature());
        return counter;
    }

    /** Creates purpose- and owner-bound random state, saves it with TTL, and returns protocol metadata.
     * @param purpose registration or authentication purpose
     * @param username normalized account name
     * @param userId account ID for authenticated challenges, or null for onboarding
     * @param sessionId signup session for onboarding, otherwise empty
     * @return client-facing challenge response
     */
    private DeviceKeyChallengeResponse issueChallenge(
            DeviceKeyChallengePurpose purpose,
            String username,
            Long userId,
            String sessionId) {
        String challengeId = UUID.randomUUID().toString();
        String challenge = randomHex(32);
        long expiresAt = Instant.now().plusSeconds(challengeTtlSeconds).getEpochSecond();
        DeviceKeyChallengeState state = new DeviceKeyChallengeState(
                challengeId,
                challenge,
                purpose,
                username,
                userId,
                sessionId,
                expiresAt);
        try {
            redisService.setValue(
                    CHALLENGE_PREFIX + challengeId,
                    objectMapper.writeValueAsString(state),
                    challengeTtlSeconds);
        } catch (Exception exception) {
            throw new DeviceKeyProtocolException("Unable to store device key challenge.", exception);
        }
        return new DeviceKeyChallengeResponse(
                challengeId,
                challenge,
                challengeTtlSeconds,
                onionServiceId,
                ALGORITHM,
                CANONICALIZATION);
    }

    /** Atomically consumes a challenge and rejects absent, expired, malformed, or already-used state.
     * @param challengeId one-time challenge identifier
     * @return validated challenge state
     */
    private DeviceKeyChallengeState consumeChallenge(String challengeId) {
        requireNonBlank(challengeId, "challengeId is required.");
        String raw = redisService.getAndDeleteValue(CHALLENGE_PREFIX + challengeId.trim());
        if (raw == null || raw.isBlank()) {
            throw new DeviceKeyChallengeException("Challenge expired, missing, or already used.");
        }
        try {
            DeviceKeyChallengeState state = objectMapper.readValue(raw, DeviceKeyChallengeState.class);
            if (state.expiresAtEpochSeconds() < Instant.now().getEpochSecond()) {
                throw new DeviceKeyChallengeException("Challenge expired.");
            }
            return state;
        } catch (DeviceKeyChallengeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new DeviceKeyProtocolException("Stored challenge is invalid.", exception);
        }
    }

    /** Builds the exact registration signed-payload field set from validated challenge and request data.
     * @param challenge consumed registration challenge
     * @param credentialId submitted credential ID
     * @param deviceInstallId submitted installation ID
     * @param publicKeySha256 Base64URL fingerprint of the submitted raw public key
     * @param counter authenticator counter
     * @param issuedAt signed creation time
     * @return canonical protocol payload
     */
    private Map<String, Object> registrationPayload(
            DeviceKeyChallengeState challenge,
            String credentialId,
            String deviceInstallId,
            String publicKeySha256,
            long counter,
            long issuedAt) {
        return Map.ofEntries(
                Map.entry("algorithm", ALGORITHM),
                Map.entry("challenge", challenge.challenge()),
                Map.entry("challengeId", challenge.challengeId()),
                Map.entry("counter", counter),
                Map.entry("credentialId", credentialId),
                Map.entry("deviceInstallId", deviceInstallId),
                Map.entry("issuedAtEpochSeconds", issuedAt),
                Map.entry("onionServiceId", onionServiceId),
                Map.entry("publicKeySha256", publicKeySha256),
                Map.entry("sessionId", normalizeRequired(challenge.sessionId(), "")),
                Map.entry("type", REGISTER_TYPE),
                Map.entry("username", normalizeUsername(challenge.username())),
                Map.entry("version", 1));
    }

    /** Builds the exact authentication signed-payload field set from the consumed challenge and credential.
     * @param challenge consumed authentication challenge
     * @param username account name
     * @param credentialId persisted credential ID
     * @param deviceInstallId bound installation ID
     * @param counter authenticator counter
     * @param issuedAt signed creation time
     * @return canonical protocol payload
     */
    private Map<String, Object> authenticationPayload(
            DeviceKeyChallengeState challenge,
            String username,
            String credentialId,
            String deviceInstallId,
            long counter,
            long issuedAt) {
        return Map.ofEntries(
                Map.entry("challenge", challenge.challenge()),
                Map.entry("challengeId", challenge.challengeId()),
                Map.entry("counter", counter),
                Map.entry("credentialId", credentialId),
                Map.entry("deviceInstallId", deviceInstallId),
                Map.entry("issuedAtEpochSeconds", issuedAt),
                Map.entry("onionServiceId", onionServiceId),
                Map.entry("type", AUTH_TYPE),
                Map.entry("username", normalizeUsername(username)),
                Map.entry("version", 1));
    }

    /** Constant-time compares submitted bytes with server-reconstructed canonical JSON and checks protocol identity.
     * @param signedPayload exact UTF-8 bytes supplied by the client
     * @param expectedPayload server-reconstructed expected fields
     */
    private void verifyCanonicalPayload(String signedPayload, Map<String, Object> expectedPayload) {
        requireNonBlank(signedPayload, "signedPayload is required.");
        String expectedCanonical = DeviceKeyCanonicalJson.canonicalize(expectedPayload);
        if (!MessageDigest.isEqual(
                expectedCanonical.getBytes(StandardCharsets.UTF_8),
                signedPayload.getBytes(StandardCharsets.UTF_8))) {
            throw new DeviceKeyProtocolException("signedPayload is not the expected canonical JSON.");
        }
        Object algorithm = expectedPayload.get("algorithm");
        if (algorithm != null && !ALGORITHM.equals(algorithm.toString())) {
            throw new DeviceKeyProtocolException("Unsupported device key algorithm.");
        }
        if (!Objects.equals(onionServiceId, expectedPayload.get("onionServiceId"))) {
            throw new DeviceKeyProtocolException("onionServiceId mismatch.");
        }
    }

    /** Parses simple JSON values and rejects nested/null data unsupported by canonicalization v1.
     * @param signedPayload client-signed JSON
     * @return insertion-ordered parsed fields
     */
    private LinkedHashMap<String, Object> parsePayload(String signedPayload) {
        requireNonBlank(signedPayload, "signedPayload is required.");
        try {
            LinkedHashMap<String, Object> payload = objectMapper.readValue(signedPayload, PAYLOAD_TYPE);
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                if (entry.getValue() == null
                        || entry.getValue() instanceof Map<?, ?>
                        || entry.getValue() instanceof Iterable<?>) {
                    throw new DeviceKeyProtocolException("Canonical JSON v1 only allows simple values.");
                }
            }
            return payload;
        } catch (DeviceKeyProtocolException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new DeviceKeyProtocolException("signedPayload is not valid JSON.", exception);
        }
    }

    /** Verifies Ed25519 over the exact signed-payload UTF-8 bytes.
     * @param publicKeyBytes raw 32-byte Ed25519 key
     * @param signedPayload exact canonical payload bytes represented as text
     * @param signatureBase64Url Base64URL or Base64 signature
     * @throws DeviceKeySignatureException when signature is invalid or verification fails
     */
    private void verifySignature(byte[] publicKeyBytes, String signedPayload, String signatureBase64Url) {
        requireNonBlank(signatureBase64Url, "signature is required.");
        try {
            PublicKey publicKey = loadEd25519PublicKey(publicKeyBytes);
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(signedPayload.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(decodeBase64Flexible(signatureBase64Url, "signature"))) {
                throw new DeviceKeySignatureException("Device key signature rejected.");
            }
        } catch (DeviceKeySignatureException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new DeviceKeySignatureException("Unable to verify device key signature.", exception);
        }
    }

    /** Wraps a raw 32-byte Ed25519 key with its X.509 prefix and loads it via JCA.
     * @param rawKey raw Ed25519 public key
     * @return parsed key
     * @throws Exception when size or JCA decoding is invalid
     */
    private PublicKey loadEd25519PublicKey(byte[] rawKey) throws Exception {
        if (rawKey.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be exactly 32 bytes.");
        }
        byte[] x509Key = new byte[ED25519_X509_PREFIX.length + rawKey.length];
        System.arraycopy(ED25519_X509_PREFIX, 0, x509Key, 0, ED25519_X509_PREFIX.length);
        System.arraycopy(rawKey, 0, x509Key, ED25519_X509_PREFIX.length, rawKey.length);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(x509Key));
    }

    /** Rejects nonpositive timestamps and timestamps more than 30 seconds in the future.
     * @param issuedAtEpochSeconds signed client timestamp
     */
    private void validateIssuedAt(long issuedAtEpochSeconds) {
        long now = Instant.now().getEpochSecond();
        if (issuedAtEpochSeconds <= 0 || issuedAtEpochSeconds > now + 30) {
            throw new DeviceKeyProtocolException("issuedAtEpochSeconds is invalid.");
        }
    }

    /** Reads an integer-valued payload field without accepting strings or absent values.
     * @param payload parsed signed fields
     * @param field required field name
     * @return numeric field as long
     */
    private long longField(Map<String, Object> payload, String field) {
        Object value = payload.get(field);
        if (value instanceof Number number) {
            return number.longValue();
        }
        throw new DeviceKeyProtocolException(field + " must be an integer.");
    }

    /** Reads and trims a non-empty string field from a parsed payload.
     * @param payload parsed signed fields
     * @param field required field name
     * @return trimmed field value
     */
    private String stringField(Map<String, Object> payload, String field) {
        Object value = payload.get(field);
        if (value instanceof String string && !string.isBlank()) {
            return string.trim();
        }
        throw new DeviceKeyProtocolException(field + " must be a non-empty string.");
    }

    /** Decodes padded or unpadded Base64URL first, then standard Base64, wrapping invalid input.
     * @param value encoded text
     * @param label field label used in validation errors
     * @return decoded bytes
     */
    private byte[] decodeBase64Flexible(String value, String label) {
        requireNonBlank(value, label + " is required.");
        String normalized = value.trim();
        try {
            return Base64.getUrlDecoder().decode(padBase64(normalized));
        } catch (IllegalArgumentException ignored) {
            try {
                return Base64.getDecoder().decode(normalized);
            } catch (IllegalArgumentException exception) {
                throw new DeviceKeyProtocolException(label + " is not valid base64.", exception);
            }
        }
    }

    /** Adds required padding to a Base64URL value for the Java decoder.
     * @param value unpadded or padded input
     * @return value with a multiple-of-four character length
     */
    private String padBase64(String value) {
        int remainder = value.length() % 4;
        return remainder == 0 ? value : value + "=".repeat(4 - remainder);
    }

    /** Produces secure random bytes and encodes them as lowercase hexadecimal.
     * @param byteCount number of random bytes
     * @return hex string twice the requested byte count
     */
    private String randomHex(int byteCount) {
        byte[] bytes = new byte[byteCount];
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /** Computes SHA-256 and wraps provider failures as service initialization errors.
     * @param input bytes to hash
     * @return digest bytes
     */
    private byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    /** Encodes bytes using unpadded Base64URL.
     * @param bytes source bytes
     * @return URL-safe text
     */
    private String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Trims and lowercases usernames with locale-independent casing.
     * @param username submitted username
     * @return normalized username, or empty string for null
     */
    private String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    /** Trims required configuration, returning a fallback when blank.
     * @param value configured value
     * @param fallback fallback for null/blank
     * @return normalized value
     */
    private String normalizeRequired(String value, String fallback) {
        String normalized = value == null ? "" : value.trim();
        return normalized.isEmpty() ? fallback : normalized;
    }

    /** Returns trimmed nonblank text or a fallback.
     * @param value candidate value
     * @param fallback fallback value
     * @return normalized text or fallback
     */
    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    /** Rejects null or blank protocol values.
     * @param value candidate value
     * @param message protocol error message
     * @throws DeviceKeyProtocolException when value is absent
     */
    private void requireNonBlank(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new DeviceKeyProtocolException(message);
        }
    }

    /**
     * Registration proof material and client/device metadata after protocol verification.
     * @param credentialId authenticator credential identifier
     * @param userHandle user handle, falling back to credential ID
     * @param publicKeyEd25519 encoded public key material
     * @param publicKeySha256 fingerprint of decoded public key bytes
     * @param counter initial authenticator counter
     * @param deviceName display name
     * @param deviceInstallId stable installation identifier
     * @param keyStorage declared key storage class
     * @param platform client platform
     * @param browser client browser
     * @param brand device brand
     * @param model device model
     * @param serialNumber device serial metadata
     * @param onionServiceId server identity included in the challenge
     */
    public record VerifiedDeviceKeyRegistration(
            String credentialId,
            String userHandle,
            String publicKeyEd25519,
            String publicKeySha256,
            long counter,
            String deviceName,
            String deviceInstallId,
            String keyStorage,
            String platform,
            String browser,
            String brand,
            String model,
            String serialNumber,
            String onionServiceId) {
    }

    /** Jackson map type for parsing the simple string-keyed signed payload protocol. */
    private static final class DeviceKeyPayloadType extends TypeReference<LinkedHashMap<String, Object>> {
    }
}
