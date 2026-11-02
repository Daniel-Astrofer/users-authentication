package com.kerosene.auth.application.usecase.security;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.orchestrator.login.LoginThrottlePolicy;
import com.kerosene.auth.application.service.account.AppPinService;
import com.kerosene.auth.application.service.authentication.contracts.LoginVerifier;
import com.kerosene.auth.application.service.devicebinding.DeviceCredentialReplayGuard;
import com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.dto.AppPinStatusDTO;
import com.kerosene.auth.dto.RecoverAppPinRequestDTO;
import com.kerosene.auth.dto.UserDTO;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.common.exception.ErrorCodes;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/** Replaces a device PIN only after both fresh password and registered-device proofs succeed. */
@Component
public class RecoverAppPinUseCase {
    private final UserServiceContract users;
    private final LoginVerifier passwords;
    private final LoginThrottlePolicy throttle;
    private final DeviceKeyCredentialRepository credentials;
    private final DeviceKeyService deviceKeys;
    private final DeviceCredentialReplayGuard replayGuard;
    private final AppPinService pins;

    /** Creates the recovery boundary from existing password, device-proof, and PIN operations. */
    public RecoverAppPinUseCase(UserServiceContract users, LoginVerifier passwords,
            LoginThrottlePolicy throttle, DeviceKeyCredentialRepository credentials,
            DeviceKeyService deviceKeys, DeviceCredentialReplayGuard replayGuard, AppPinService pins) {
        this.users = users;
        this.passwords = passwords;
        this.throttle = throttle;
        this.credentials = credentials;
        this.deviceKeys = deviceKeys;
        this.replayGuard = replayGuard;
        this.pins = pins;
    }

    /**
     * Consumes a fresh account-owned device assertion and atomically updates its counter and PIN.
     * An invalid factor returns a client-factor error rather than invalidating the bearer session.
     * Existing current-PIN/TOTP configuration and legacy PIN verification remain unchanged.
     *
     * @param deviceHash current device's PIN scope
     * @param request account password, four-digit replacement, and fresh device-key assertion
     * @return updated PIN status after both account factors have been verified
     */
    @Transactional
    public AppPinStatusDTO execute(String deviceHash, RecoverAppPinRequestDTO request) {
        try {
            UserDataBase user = authenticatedUser();
            validateInput(deviceHash, request);
            verifyPassword(user, request.getPassword());

            var proof = request.getDeviceKey();
            if (proof.getUsername() != null && !proof.getUsername().isBlank()
                    && !user.getUsername().equalsIgnoreCase(proof.getUsername().trim())) {
                throw rejected();
            }
            String id = proof.getCredentialId().trim();
            var credential = credentials.findByCredentialIdAndUserId(id, user.getId())
                    .orElseThrow(RecoverAppPinUseCase::rejected);
            String credentialRef = DeviceCredentialReplayGuard.credentialRefFromString(id);
            if (credential.getUser() == null || !Objects.equals(credential.getUser().getId(), user.getId())
                    || credential.getRevokedAt() != null || !"ACTIVE".equals(credential.getStatus())
                    || replayGuard.isLocked(user.getId(), credentialRef)) {
                throw rejected();
            }
            final long counter;
            try {
                counter = deviceKeys.verifyAuthentication(proof, user, credential);
            } catch (DeviceKeyProtocolException failure) {
                throw rejected();
            }
            if (credentials.advanceCounter(id, user.getId(), counter, LocalDateTime.now()) != 1) {
                replayGuard.recordReplayFailure(user.getId(), credentialRef, "APP_PIN_RECOVERY");
                throw rejected();
            }
            AppPinStatusDTO status = pins.recoverWithVerifiedAccountFactors(user, deviceHash, request.getNewPin());
            replayGuard.clearFailures(user.getId(), credentialRef);
            return status;
        } finally {
            if (request != null && request.getPassword() != null) {
                Arrays.fill(request.getPassword(), '\0');
            }
        }
    }

    private UserDataBase authenticatedUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthExceptions.InvalidCredentials("Not authenticated.");
        }
        try {
            return users.buscarPorId(Long.parseLong(authentication.getName()))
                    .filter(user -> Boolean.TRUE.equals(user.getIsActive()))
                    .orElseThrow(() -> new AuthExceptions.InvalidCredentials("Authenticated user not found."));
        } catch (NumberFormatException failure) {
            throw new AuthExceptions.InvalidCredentials("Invalid authentication context.");
        }
    }

    private void validateInput(String deviceHash, RecoverAppPinRequestDTO request) {
        if (deviceHash == null || deviceHash.isBlank() || deviceHash.trim().length() > 128
                || request == null || request.getPassword() == null || request.getPassword().length == 0
                || request.getNewPin() == null || !request.getNewPin().matches("[0-9]{4}")
                || request.getDeviceKey() == null || request.getDeviceKey().getCredentialId() == null
                || request.getDeviceKey().getCredentialId().isBlank()) {
            throw rejected();
        }
    }

    private void verifyPassword(UserDataBase user, char[] password) {
        String username = user.getUsername().trim().toLowerCase(Locale.ROOT);
        UserDTO login = new UserDTO();
        login.setUsername(username);
        login.setPassphrase(password);
        try {
            throttle.ensureLoginAllowed(username);
            UserDataBase verified = passwords.matcherWithoutDevice(login);
            if (verified == null || !Objects.equals(verified.getId(), user.getId())) {
                throw new AuthExceptions.InvalidCredentials("Invalid recovery account.");
            }
            throttle.clearLoginFailures(username);
        } catch (AuthExceptions.InvalidCredentials failure) {
            throttle.recordLoginFailure(username);
            throw rejected();
        }
    }

    private static AuthExceptions.StructuredAuthException rejected() {
        return new AuthExceptions.StructuredAuthException(
                "Confirme a senha da conta e uma passkey cadastrada para redefinir o PIN.",
                HttpStatus.BAD_REQUEST, ErrorCodes.AUTH_INVALID_CREDENTIALS, null);
    }
}
