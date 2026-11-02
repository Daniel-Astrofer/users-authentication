package com.kerosene.auth.application.service.account;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.jpa.UserAppPinSettingsRepository;
import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.model.entity.UserAppPinSettings;
import com.kerosene.auth.model.entity.UserDataBase;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AppPinRecoveryTest {
    @Test
    void verifiedRecoveryInstallsNewHashAndClearsDeviceLockoutWithoutRetainingPinBuffer() {
        var repository = mock(UserAppPinSettingsRepository.class);
        var hasher = mock(Hasher.class);
        var user = new UserDataBase();
        org.springframework.test.util.ReflectionTestUtils.setField(user, "id", 42L);
        var settings = new UserAppPinSettings();
        settings.setUser(user);
        settings.setDeviceHash("device-42");
        settings.setEnabled(true);
        settings.setPinHash("old-hash");
        settings.setFailedAttempts(5);
        settings.setLockedUntil(LocalDateTime.now().plusMinutes(5));
        settings.setLastVerifiedAt(LocalDateTime.now().minusDays(1));
        when(repository.findByUserIdAndDeviceHash(42L, "device-42")).thenReturn(Optional.of(settings));
        final char[][] captured = new char[1][];
        when(hasher.hash(any())).thenAnswer(invocation -> {
            captured[0] = invocation.getArgument(0, char[].class);
            assertThat(captured[0]).containsExactly('0', '4', '7', '2');
            return "new-hash";
        });
        var pins = new AppPinService(repository, hasher, mock(TOTPVerifier.class), 4, 8, 5, 5);

        var result = pins.recoverWithVerifiedAccountFactors(user, "device-42", "0472");

        assertThat(result.enabled()).isTrue();
        assertThat(result.configured()).isTrue();
        assertThat(settings.getPinHash()).isEqualTo("new-hash");
        assertThat(settings.getFailedAttempts()).isZero();
        assertThat(settings.getLockedUntil()).isNull();
        assertThat(settings.getLastVerifiedAt()).isNull();
        assertThat(captured[0]).containsOnly('\0');
        verify(repository).save(settings);
    }

    @Test
    void legacyLongPinsRemainVerifiableButRecoveryCannotCreateAnotherLongPin() {
        var repository = mock(UserAppPinSettingsRepository.class);
        var hasher = mock(Hasher.class);
        var user = new UserDataBase();
        org.springframework.test.util.ReflectionTestUtils.setField(user, "id", 42L);
        var settings = new UserAppPinSettings();
        settings.setEnabled(true);
        settings.setPinHash("legacy-hash");
        when(repository.findByUserIdAndDeviceHash(42L, "device-42")).thenReturn(Optional.of(settings));
        when(hasher.verify(any(), eq("legacy-hash"))).thenReturn(true);
        var pins = new AppPinService(repository, hasher, mock(TOTPVerifier.class), 4, 8, 5, 5);

        assertThat(pins.verify(user, "device-42", "12345678").configured()).isTrue();
        assertThatThrownBy(() -> pins.recoverWithVerifiedAccountFactors(user, "device-42", "12345678"))
                .isInstanceOf(AuthExceptions.InvalidCredentials.class);
        verify(hasher, never()).hash(any());
    }

    @Test
    void recoveryCannotOverrideADeploymentWithStricterPinPolicy() {
        var repository = mock(UserAppPinSettingsRepository.class);
        var hasher = mock(Hasher.class);
        var pins = new AppPinService(repository, hasher, mock(TOTPVerifier.class), 6, 8, 5, 5);
        assertThatThrownBy(() -> pins.recoverWithVerifiedAccountFactors(new UserDataBase(), "device-42", "0472"))
                .isInstanceOf(AuthExceptions.InvalidCredentials.class);
        verifyNoInteractions(repository, hasher);
    }
}
