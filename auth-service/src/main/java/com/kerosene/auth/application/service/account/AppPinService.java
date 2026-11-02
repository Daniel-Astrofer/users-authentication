package com.kerosene.auth.application.service.account;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.jpa.UserAppPinSettingsRepository;
import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.dto.AppPinStatusDTO;
import com.kerosene.auth.dto.ConfigureAppPinRequestDTO;
import com.kerosene.auth.model.entity.UserAppPinSettings;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.common.exception.ErrorCodes;

import java.time.LocalDateTime;
import java.util.Arrays;

/** Manages a numeric application PIN scoped to a user/device pair with lockout and TOTP recovery. */
@Service
public class AppPinService {

    /** Repository for per-device PIN settings and write-locked updates. */
    private final UserAppPinSettingsRepository repository;
    /** Argon2-qualified hasher used to store and compare PINs. */
    private final Hasher hasher;
    /** TOTP verifier used to authorize PIN replacement when the current PIN is unavailable. */
    private final TOTPVerifier totpVerifier;
    /** Minimum accepted PIN digit count. */
    private final int minPinLength;
    /** Maximum accepted PIN digit count. */
    private final int maxPinLength;
    /** Failed verification count that triggers a temporary lock. */
    private final int maxAttempts;
    /** Duration applied to a lock after reaching the failed-attempt limit. */
    private final int lockoutMinutes;

    /**
     * Creates the PIN service with repository, cryptographic, TOTP, and configurable policy limits.
     *
     * @param repository per-device PIN settings repository
     * @param hasher Argon2 PIN hashing/verifying implementation
     * @param totpVerifier TOTP recovery-factor verifier
     * @param minPinLength minimum allowed PIN length
     * @param maxPinLength maximum allowed PIN length
     * @param maxAttempts failures before lockout
     * @param lockoutMinutes lock duration in minutes
     */
    public AppPinService(
            UserAppPinSettingsRepository repository,
            @Qualifier("Argon2Hasher") Hasher hasher,
            TOTPVerifier totpVerifier,
            @Value("${security.app-pin.min-length:4}") int minPinLength,
            @Value("${security.app-pin.max-length:8}") int maxPinLength,
            @Value("${security.app-pin.max-attempts:5}") int maxAttempts,
            @Value("${security.app-pin.lockout-minutes:5}") int lockoutMinutes) {
        this.repository = repository;
        this.hasher = hasher;
        this.totpVerifier = totpVerifier;
        this.minPinLength = minPinLength;
        this.maxPinLength = maxPinLength;
        this.maxAttempts = maxAttempts;
        this.lockoutMinutes = lockoutMinutes;
    }

    /**
     * Enables or disables PIN protection for one device. Reconfiguration of an enabled PIN requires
     * either the current PIN or an active account TOTP; enabling hashes the new PIN and resets counters.
     *
     * @param user account that owns the device PIN
     * @param deviceHash device identifier to scope settings
     * @param request requested enabled state and authorization material
     * @return resulting status for this user/device pair
     */
    @Transactional
    public AppPinStatusDTO configure(UserDataBase user, String deviceHash, ConfigureAppPinRequestDTO request) {
        String normalizedDeviceHash = normalizeDeviceHash(deviceHash);
        boolean enable = Boolean.TRUE.equals(request.getEnabled());
        UserAppPinSettings settings = repository.findByUserIdAndDeviceHash(user.getId(), normalizedDeviceHash)
                .map(this::resetExpiredLockIfNeeded)
                .orElseGet(() -> newSettings(user, normalizedDeviceHash));

        if (enable) {
            String newPin = normalizedPin(request.getPin(), true);
            if (isEnabled(settings)) {
                authorizeExistingSettings(user, settings, request.getCurrentPin(), request.getTotpCode());
            }

            settings.setEnabled(true);
            settings.setPinHash(hashPin(newPin));
            settings.setFailedAttempts(0);
            settings.setLockedUntil(null);
            settings.setLastVerifiedAt(null);
            repository.save(settings);
            return toStatus(user, settings);
        }

        if (isEnabled(settings)) {
            authorizeExistingSettings(user, settings, request.getCurrentPin(), request.getTotpCode());
        }

        settings.setEnabled(false);
        settings.setPinHash(null);
        settings.setFailedAttempts(0);
        settings.setLockedUntil(null);
        settings.setLastVerifiedAt(null);
        repository.save(settings);
        return toStatus(user, settings);
    }

    /**
     * Replaces a device PIN after the recovery use case verifies the account password and a fresh,
     * registered device-key assertion. This method must only be called behind that factor boundary.
     * Recovery clears PIN lockout without weakening the current-PIN/TOTP configuration operation.
     *
     * @param user account whose two recovery factors were verified
     * @param deviceHash target device's PIN scope
     * @param newPin replacement containing exactly four ASCII digits
     * @return enabled PIN status with cleared attempts and lockout
     */
    @Transactional
    public AppPinStatusDTO recoverWithVerifiedAccountFactors(UserDataBase user, String deviceHash, String newPin) {
        if (newPin == null || !newPin.matches("[0-9]{4}")) {
            throw new AuthExceptions.InvalidCredentials("O novo PIN deve conter exatamente 4 digitos.");
        }
        String validatedNewPin = normalizedPin(newPin, true);
        String normalizedDeviceHash = normalizeDeviceHash(deviceHash);
        UserAppPinSettings settings = repository.findByUserIdAndDeviceHash(user.getId(), normalizedDeviceHash)
                .orElseGet(() -> newSettings(user, normalizedDeviceHash));
        settings.setEnabled(true);
        settings.setPinHash(hashPin(validatedNewPin));
        settings.setFailedAttempts(0);
        settings.setLockedUntil(null);
        settings.setLastVerifiedAt(null);
        repository.save(settings);
        return toStatus(user, settings);
    }

    /**
     * Checks the device PIN in an independent transaction so rejected attempts and lockout state
     * survive any caller rollback. A wrong PIN is a local-factor client error, while the threshold
     * failure returns a rate-limited lock response.
     *
     * @param user account that owns the device PIN
     * @param deviceHash device identifier to scope settings
     * @param pin submitted numeric PIN
     * @return updated PIN status after successful verification
     */
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW,
            noRollbackFor = AuthExceptions.StructuredAuthException.class)
    public AppPinStatusDTO verify(UserDataBase user, String deviceHash, String pin) {
        String normalizedDeviceHash = normalizeDeviceHash(deviceHash);
        UserAppPinSettings settings = repository.findByUserIdAndDeviceHash(user.getId(), normalizedDeviceHash)
                .map(this::resetExpiredLockIfNeeded)
                .orElseThrow(() -> notConfigured(user, normalizedDeviceHash));

        if (!isEnabled(settings)) {
            throw notConfigured(user, normalizedDeviceHash);
        }

        assertNotLocked(user, settings);
        String normalizedPin = normalizedPin(pin, true);

        if (matchesPin(normalizedPin, settings.getPinHash())) {
            settings.setFailedAttempts(0);
            settings.setLockedUntil(null);
            settings.setLastVerifiedAt(LocalDateTime.now());
            repository.save(settings);
            return toStatus(user, settings);
        }

        int failedAttempts = (settings.getFailedAttempts() != null ? settings.getFailedAttempts() : 0) + 1;
        settings.setFailedAttempts(failedAttempts);

        if (failedAttempts >= maxAttempts) {
            settings.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutMinutes));
            repository.save(settings);
            throw new AuthExceptions.StructuredAuthException(
                    "PIN temporariamente bloqueado por excesso de tentativas.",
                    HttpStatus.TOO_MANY_REQUESTS,
                    ErrorCodes.AUTH_APP_PIN_LOCKED,
                    toStatus(user, settings));
        }

        repository.save(settings);
        // BAD_REQUEST (not 401): wrong PIN is a local factor failure.
        // 401 is reserved for invalid/expired JWT sessions and would log the app out.
        throw new AuthExceptions.StructuredAuthException(
                "PIN numerico incorreto.",
                HttpStatus.BAD_REQUEST,
                ErrorCodes.AUTH_APP_PIN_INVALID,
                toStatus(user, settings));
    }

    /**
     * Returns current PIN policy/status and resets an expired lock when the device is identified.
     * An absent optional device hash yields disabled/default status without creating a settings row.
     *
     * @param user account that owns the device PIN
     * @param deviceHash optional device identifier
     * @return PIN status projection
     */
    @Transactional
    public AppPinStatusDTO getStatus(UserDataBase user, String deviceHash) {
        String normalizedDeviceHash = normalizeOptionalDeviceHash(deviceHash);
        if (normalizedDeviceHash == null) {
            return toStatus(user, null);
        }
        UserAppPinSettings settings = repository.findByUserIdAndDeviceHash(user.getId(), normalizedDeviceHash)
                .map(this::resetExpiredLockIfNeeded)
                .orElse(null);
        return toStatus(user, settings);
    }

    /**
     * Creates disabled settings for a previously unseen owner/device pair without persisting them.
     *
     * @param user owning account
     * @param deviceHash normalized device identifier
     * @return unsaved settings initialized with zero failures
     */
    private UserAppPinSettings newSettings(UserDataBase user, String deviceHash) {
        UserAppPinSettings settings = new UserAppPinSettings();
        settings.setUser(user);
        settings.setDeviceHash(deviceHash);
        settings.setEnabled(false);
        settings.setFailedAttempts(0);
        return settings;
    }

    /**
     * Clears an elapsed lock and its failures, persisting the reset while retaining other settings.
     *
     * @param settings loaded device PIN settings
     * @return original settings or persisted reset settings
     */
    private UserAppPinSettings resetExpiredLockIfNeeded(UserAppPinSettings settings) {
        if (settings.getLockedUntil() != null && LocalDateTime.now().isAfter(settings.getLockedUntil())) {
            settings.setLockedUntil(null);
            settings.setFailedAttempts(0);
            return repository.save(settings);
        }
        return settings;
    }

    /**
     * Authorizes replacing or disabling an enabled PIN with the current PIN or a valid active TOTP code.
     *
     * @param user account owning the settings
     * @param settings current PIN settings
     * @param currentPin optional current PIN
     * @param totpCode optional recovery TOTP
     */
    private void authorizeExistingSettings(
            UserDataBase user,
            UserAppPinSettings settings,
            String currentPin,
            String totpCode) {
        String normalizedCurrentPin = normalizedPin(currentPin, false);
        if (normalizedCurrentPin != null) {
            assertNotLocked(user, settings);
            if (!matchesPin(normalizedCurrentPin, settings.getPinHash())) {
                throw new AuthExceptions.StructuredAuthException(
                        "PIN atual incorreto.",
                        HttpStatus.BAD_REQUEST,
                        ErrorCodes.AUTH_APP_PIN_INVALID,
                        toStatus(user, settings));
            }
            return;
        }

        String normalizedTotp = normalizeTotpCode(totpCode);
        if (normalizedTotp != null) {
            if (!user.hasTotpEnabled()) {
                throw new AuthExceptions.InvalidCredentials(
                        "A conta nao possui TOTP ativo para redefinir o PIN do aplicativo.");
            }
            totpVerifier.totpVerify(user.getTOTPSecret(), normalizedTotp);
            return;
        }

        throw new AuthExceptions.InvalidCredentials(
                "Informe o PIN atual ou um codigo TOTP valido para alterar a protecao do aplicativo.");
    }

    /**
     * Rejects an operation while the device PIN lock deadline is still in the future.
     *
     * @param user account owning the settings
     * @param settings current PIN settings
     * @throws AuthExceptions.StructuredAuthException when lockout is active
     */
    private void assertNotLocked(UserDataBase user, UserAppPinSettings settings) {
        if (settings.getLockedUntil() != null && LocalDateTime.now().isBefore(settings.getLockedUntil())) {
            throw new AuthExceptions.StructuredAuthException(
                    "PIN temporariamente bloqueado por excesso de tentativas.",
                    HttpStatus.TOO_MANY_REQUESTS,
                    ErrorCodes.AUTH_APP_PIN_LOCKED,
                    toStatus(user, settings));
        }
    }

    /**
     * Builds a conflict error for a device without enabled PIN settings.
     *
     * @param user account requesting PIN verification
     * @param deviceHash normalized device identifier
     * @return structured not-configured error including current status
     */
    private AuthExceptions.StructuredAuthException notConfigured(UserDataBase user, String deviceHash) {
        return new AuthExceptions.StructuredAuthException(
                "PIN numerico ainda nao configurado para este dispositivo.",
                HttpStatus.CONFLICT,
                ErrorCodes.AUTH_APP_PIN_NOT_CONFIGURED,
                getStatus(user, deviceHash));
    }

    /**
     * Projects configuration limits, lock status, remaining attempts, and timestamps for the client.
     *
     * @param user account whose TOTP state is included
     * @param settings current device settings, or {@code null} when absent
     * @return app-PIN status DTO
     */
    private AppPinStatusDTO toStatus(UserDataBase user, UserAppPinSettings settings) {
        boolean enabled = isEnabled(settings);
        int failedAttempts = settings != null && settings.getFailedAttempts() != null ? settings.getFailedAttempts() : 0;
        boolean locked = settings != null
                && settings.getLockedUntil() != null
                && LocalDateTime.now().isBefore(settings.getLockedUntil());
        int remainingAttempts = locked ? 0 : Math.max(0, maxAttempts - failedAttempts);
        return new AppPinStatusDTO(
                enabled,
                enabled,
                locked,
                failedAttempts,
                remainingAttempts,
                maxAttempts,
                minPinLength,
                maxPinLength,
                user.hasTotpEnabled(),
                true,
                settings != null ? settings.getLockedUntil() : null,
                settings != null ? settings.getLastVerifiedAt() : null,
                settings != null ? settings.getUpdatedAt() : null);
    }

    /**
     * Requires both an enabled flag and a non-empty stored hash to consider PIN protection active.
     *
     * @param settings device settings, possibly absent
     * @return true only for complete enabled settings
     */
    private boolean isEnabled(UserAppPinSettings settings) {
        return settings != null
                && Boolean.TRUE.equals(settings.getEnabled())
                && settings.getPinHash() != null
                && !settings.getPinHash().isBlank();
    }

    /**
     * Requires and normalizes a device identifier before read/write PIN operations.
     *
     * @param deviceHash supplied device identifier
     * @return trimmed device identifier
     * @throws AuthExceptions.StructuredAuthException when no device can be identified
     */
    private String normalizeDeviceHash(String deviceHash) {
        String normalized = normalizeOptionalDeviceHash(deviceHash);
        if (normalized == null) {
            throw new AuthExceptions.StructuredAuthException(
                    "O dispositivo atual nao foi identificado.",
                    HttpStatus.BAD_REQUEST,
                    ErrorCodes.AUTH_APP_PIN_DEVICE_REQUIRED,
                    null);
        }
        return normalized;
    }

    /**
     * Trims an optional device identifier and rejects values exceeding the storage bound.
     *
     * @param deviceHash supplied identifier
     * @return trimmed identifier or {@code null} when absent
     * @throws AuthExceptions.InvalidCredentials when identifier exceeds 128 characters
     */
    private String normalizeOptionalDeviceHash(String deviceHash) {
        if (deviceHash == null || deviceHash.isBlank()) {
            return null;
        }
        String normalized = deviceHash.trim();
        if (normalized.length() > 128) {
            throw new AuthExceptions.InvalidCredentials("Identificador do dispositivo invalido.");
        }
        return normalized;
    }

    /**
     * Trims and validates a numeric PIN against configured digit bounds.
     *
     * @param pin candidate PIN
     * @param required whether absent input is an error
     * @return normalized PIN or {@code null} when optional input is absent
     * @throws AuthExceptions.InvalidCredentials for absent required, nonnumeric, or out-of-range input
     */
    private String normalizedPin(String pin, boolean required) {
        if (pin == null || pin.isBlank()) {
            if (required) {
                throw new AuthExceptions.InvalidCredentials("Informe um PIN numerico.");
            }
            return null;
        }

        String normalized = pin.trim();
        if (!normalized.chars().allMatch(Character::isDigit)) {
            throw new AuthExceptions.InvalidCredentials("O PIN deve conter apenas numeros.");
        }
        if (normalized.length() < minPinLength || normalized.length() > maxPinLength) {
            throw new AuthExceptions.InvalidCredentials(
                    "O PIN deve ter entre " + minPinLength + " e " + maxPinLength + " digitos.");
        }
        return normalized;
    }

    /**
     * Trims and validates an optional six-digit numeric TOTP value.
     *
     * @param totpCode candidate TOTP code
     * @return normalized code or {@code null} when absent
     * @throws AuthExceptions.InvalidCredentials for malformed non-empty input
     */
    private String normalizeTotpCode(String totpCode) {
        if (totpCode == null || totpCode.isBlank()) {
            return null;
        }
        String normalized = totpCode.trim();
        if (!normalized.chars().allMatch(Character::isDigit) || normalized.length() != 6) {
            throw new AuthExceptions.InvalidCredentials("O codigo TOTP deve conter 6 digitos.");
        }
        return normalized;
    }

    /**
     * Hashes a PIN using a temporary character array and clears that array in a finally block.
     *
     * @param pin normalized PIN value
     * @return encoded Argon2 hash
     */
    private String hashPin(String pin) {
        char[] pinChars = pin.toCharArray();
        try {
            return hasher.hash(pinChars);
        } finally {
            Arrays.fill(pinChars, '\0');
        }
    }

    /**
     * Verifies a candidate against the stored hash and clears the temporary character array.
     *
     * @param pin normalized candidate PIN
     * @param pinHash persisted encoded Argon2 hash
     * @return true when the hash verification succeeds
     */
    private boolean matchesPin(String pin, String pinHash) {
        char[] pinChars = pin.toCharArray();
        try {
            return Boolean.TRUE.equals(hasher.verify(pinChars, pinHash));
        } finally {
            Arrays.fill(pinChars, '\0');
        }
    }
}
