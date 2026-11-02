package com.kerosene.auth.application.usecase.devicekey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.orchestrator.signup.port.SignupStateStore;
import com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.SignupState;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FinishOnboardingDeviceKeyRegistrationUseCaseTest {

    private SignupStateStore signupStateStore;
    private DeviceKeyService deviceKeyService;
    private FinalizeSignupAccount finalizeSignupAccount;
    private DeviceKeyCredentialRepository deviceKeyRepository;
    private JwtServicer jwtServicer;
    private FinishOnboardingDeviceKeyRegistrationUseCase useCase;

    @BeforeEach
    void setUp() {
        signupStateStore = mock(SignupStateStore.class);
        deviceKeyService = mock(DeviceKeyService.class);
        finalizeSignupAccount = mock(FinalizeSignupAccount.class);
        deviceKeyRepository = mock(DeviceKeyCredentialRepository.class);
        jwtServicer = mock(JwtServicer.class);
        useCase = new FinishOnboardingDeviceKeyRegistrationUseCase(
                signupStateStore,
                deviceKeyService,
                finalizeSignupAccount,
                deviceKeyRepository,
                jwtServicer,
                mock(DeviceBindingPolicy.class));
    }

    @Test
    void returnsSessionExpiredWhenSignupStateIsMissing() {
        DeviceKeyRegistrationRequest request = new DeviceKeyRegistrationRequest();
        when(signupStateStore.findSignupState("session-1")).thenReturn(null);

        FinishOnboardingDeviceKeyRegistrationUseCase.Result result = useCase.execute("session-1", request);

        assertThat(result.status()).isEqualTo(FinishOnboardingDeviceKeyRegistrationUseCase.Status.SESSION_EXPIRED);
        assertThat(result.token()).isNull();
        verify(deviceKeyService, never()).verifyRegistration(any(), any(), any());
        verify(finalizeSignupAccount, never()).execute(any());
        verify(deviceKeyRepository, never()).save(any());
    }

    @Test
    void finishesSignupPersistsCredentialAndReturnsUserIdPrefixedToken() {
        SignupState state = new SignupState();
        state.setUsername("alice");
        DeviceKeyRegistrationRequest request = new DeviceKeyRegistrationRequest();
        UserDataBase user = user(42L, "alice");
        DeviceKeyService.VerifiedDeviceKeyRegistration verified = verifiedRegistration();
        when(signupStateStore.findSignupState("session-1")).thenReturn(state);
        when(deviceKeyService.verifyRegistration(request, "session-1", "alice")).thenReturn(verified);
        when(finalizeSignupAccount.execute("session-1")).thenReturn(user);
        when(deviceKeyRepository.findByCredentialIdAndUserId("credential-1", 42L)).thenReturn(Optional.empty());
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L)).thenReturn("jwt-token");

        FinishOnboardingDeviceKeyRegistrationUseCase.Result result = useCase.execute("session-1", request);

        assertThat(result.status()).isEqualTo(FinishOnboardingDeviceKeyRegistrationUseCase.Status.CREATED);
        assertThat(result.token()).isEqualTo("42 jwt-token");
        assertThat(state.isDeviceKeyRegistered()).isTrue();
        assertThat(state.isPasskeyRegistered()).isTrue();
        verify(signupStateStore).saveSignupState("session-1", state, Duration.ofMinutes(1440));
        verify(finalizeSignupAccount).execute("session-1");

        ArgumentCaptor<DeviceKeyCredential> credentialCaptor = ArgumentCaptor.forClass(DeviceKeyCredential.class);
        verify(deviceKeyRepository).save(credentialCaptor.capture());
        DeviceKeyCredential credential = credentialCaptor.getValue();
        assertThat(credential.getUser()).isEqualTo(user);
        assertThat(credential.getCredentialId()).isEqualTo("credential-1");
        assertThat(credential.getUserHandle()).isEqualTo("user-handle");
        assertThat(credential.getPublicKeyEd25519()).isEqualTo("public-key");
        assertThat(credential.getAlgorithm()).isEqualTo(DeviceKeyService.ALGORITHM);
        assertThat(credential.getCounter()).isEqualTo(7L);
        assertThat(credential.getDeviceName()).isEqualTo("Work laptop");
        assertThat(credential.getDeviceInstallId()).isEqualTo("install-1");
        assertThat(credential.getKeyStorage()).isEqualTo("secure-enclave");
        assertThat(credential.getPlatform()).isEqualTo("linux");
        assertThat(credential.getBrowser()).isEqualTo("firefox");
        assertThat(credential.getBrand()).isEqualTo("brand");
        assertThat(credential.getModel()).isEqualTo("model");
        assertThat(credential.getSerialNumber()).isEqualTo("serial");
        assertThat(credential.getOnionServiceId()).isEqualTo("onion");
        assertThat(credential.getProtocolVersion()).isEqualTo(1);
        assertThat(credential.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void doesNotPersistWhenCredentialIsAlreadyLinkedToUser() {
        SignupState state = new SignupState();
        state.setUsername("alice");
        DeviceKeyRegistrationRequest request = new DeviceKeyRegistrationRequest();
        UserDataBase user = user(42L, "alice");
        DeviceKeyCredential existingCredential = new DeviceKeyCredential();
        when(signupStateStore.findSignupState("session-1")).thenReturn(state);
        when(deviceKeyService.verifyRegistration(request, "session-1", "alice")).thenReturn(verifiedRegistration());
        when(finalizeSignupAccount.execute("session-1")).thenReturn(user);
        when(deviceKeyRepository.findByCredentialIdAndUserId("credential-1", 42L))
                .thenReturn(Optional.of(existingCredential));
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L)).thenReturn("jwt-token");

        FinishOnboardingDeviceKeyRegistrationUseCase.Result result = useCase.execute("session-1", request);

        assertThat(result.status()).isEqualTo(FinishOnboardingDeviceKeyRegistrationUseCase.Status.CREATED);
        assertThat(result.token()).isEqualTo("42 jwt-token");
        verify(deviceKeyRepository, never()).save(any());
    }

    private UserDataBase user(Long id, String username) {
        UserDataBase user = new UserDataBase();
        ReflectionTestUtils.setField(user, "id", id);
        user.setUsername(username);
        return user;
    }

    private DeviceKeyService.VerifiedDeviceKeyRegistration verifiedRegistration() {
        return new DeviceKeyService.VerifiedDeviceKeyRegistration(
                "credential-1",
                "user-handle",
                "public-key",
                "public-key-sha",
                7L,
                "Work laptop",
                "install-1",
                "secure-enclave",
                "linux",
                "firefox",
                "brand",
                "model",
                "serial",
                "onion");
    }
}
