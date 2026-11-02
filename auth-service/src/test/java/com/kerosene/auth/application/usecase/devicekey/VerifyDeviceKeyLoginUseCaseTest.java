package com.kerosene.auth.application.usecase.devicekey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.orchestrator.login.StartLogin;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class VerifyDeviceKeyLoginUseCaseTest {

    private DeviceKeyService deviceKeyService;
    private DeviceKeyCredentialRepository deviceKeyRepository;
    private UserRepository userRepository;
    private FinalizeSignupAccount finalizeSignupAccount;
    private JwtServicer jwtServicer;
    private RedisServicer redisService;
    private VerifyDeviceKeyLoginUseCase useCase;

    @BeforeEach
    void setUp() {
        deviceKeyService = mock(DeviceKeyService.class);
        deviceKeyRepository = mock(DeviceKeyCredentialRepository.class);
        userRepository = mock(UserRepository.class);
        finalizeSignupAccount = mock(FinalizeSignupAccount.class);
        jwtServicer = mock(JwtServicer.class);
        redisService = mock(RedisServicer.class);
        useCase = new VerifyDeviceKeyLoginUseCase(
                deviceKeyService,
                deviceKeyRepository,
                userRepository,
                finalizeSignupAccount,
                jwtServicer,
                redisService);
    }

    @Test
    void rejectsBlankCredentialId() {
        DeviceKeyVerifyRequest request = request(" ", null);

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.INVALID_CREDENTIAL_ID);
        verify(deviceKeyRepository, never()).findByCredentialId(any());
        verify(userRepository, never()).findByUsername(any());
    }

    @Test
    void returnsCredentialNotFoundWhenCredentialLookupMissesWithoutUsername() {
        DeviceKeyVerifyRequest request = request(" credential-1 ", null);
        when(deviceKeyRepository.findByCredentialId("credential-1")).thenReturn(Optional.empty());

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.CREDENTIAL_NOT_FOUND);
        verify(deviceKeyRepository).findByCredentialId("credential-1");
        verify(deviceKeyService, never()).verifyAuthentication(any(), any(), any());
    }

    @Test
    void normalizesUsernameAndReturnsUserNotFound() {
        DeviceKeyVerifyRequest request = request("credential-1", "  Alice  ");
        when(userRepository.findByUsername("alice")).thenReturn(null);

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.USER_NOT_FOUND);
        verify(userRepository).findByUsername("alice");
        verify(deviceKeyRepository, never()).findByCredentialIdAndUserId(any(), any());
    }

    @Test
    void returnsCredentialNotFoundWhenCredentialIsNotLinkedToUser() {
        UserDataBase user = user(42L, "alice", true, null);
        DeviceKeyVerifyRequest request = request(" credential-1 ", "alice");
        when(userRepository.findByUsername("alice")).thenReturn(user);
        when(deviceKeyRepository.findByCredentialIdAndUserId("credential-1", 42L)).thenReturn(Optional.empty());

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.CREDENTIAL_NOT_FOUND);
        verify(deviceKeyService, never()).verifyAuthentication(any(), any(), any());
    }

    @Test
    void returnsReplayWhenCounterDoesNotAdvance() {
        UserDataBase user = user(42L, "alice", true, null);
        DeviceKeyCredential credential = credential("credential-1", user);
        DeviceKeyVerifyRequest request = request("credential-1", null);
        when(deviceKeyRepository.findByCredentialId("credential-1")).thenReturn(Optional.of(credential));
        when(deviceKeyService.verifyAuthentication(request, user, credential)).thenReturn(9L);
        when(deviceKeyRepository.advanceCounter(eq("credential-1"), eq(42L), eq(9L), any(LocalDateTime.class)))
                .thenReturn(0);

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.REPLAY_COUNTER_NOT_ADVANCED);
        verify(finalizeSignupAccount, never()).ensureUserFinancialsReady(any(), any());
    }

    @Test
    void returnsInactiveAfterFinancialReadinessWhenAccountIsInactive() {
        UserDataBase user = user(42L, "alice", false, null);
        DeviceKeyCredential credential = credential("credential-1", user);
        DeviceKeyVerifyRequest request = request("credential-1", null);
        when(deviceKeyRepository.findByCredentialId("credential-1")).thenReturn(Optional.of(credential));
        when(deviceKeyService.verifyAuthentication(request, user, credential)).thenReturn(9L);
        when(deviceKeyRepository.advanceCounter(eq("credential-1"), eq(42L), eq(9L), any(LocalDateTime.class)))
                .thenReturn(1);

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.INACTIVE_ACCOUNT);
        verify(finalizeSignupAccount).ensureUserFinancialsReady(user, null);
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(anyLong(), org.mockito.ArgumentMatchers.anyCollection(), anyLong());
    }

    @Test
    void returnsPreAuthTokenAndCachesUsernameWhenTotpIsEnabled() {
        UserDataBase user = user(42L, "alice", true, "totp-secret");
        DeviceKeyCredential credential = credential("credential-1", user);
        DeviceKeyVerifyRequest request = request("credential-1", null);
        when(deviceKeyRepository.findByCredentialId("credential-1")).thenReturn(Optional.of(credential));
        when(deviceKeyService.verifyAuthentication(request, user, credential)).thenReturn(9L);
        when(deviceKeyRepository.advanceCounter(eq("credential-1"), eq(42L), eq(9L), any(LocalDateTime.class)))
                .thenReturn(1);

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.TOTP_REQUIRED);
        assertThat(result.data()).isInstanceOf(String.class);
        verify(redisService).setValue(
                startsWith(StartLogin.preAuthKey("")),
                eq("alice"),
                eq(StartLogin.PRE_AUTH_TTL_SECONDS));
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(anyLong(), org.mockito.ArgumentMatchers.anyCollection(), anyLong());
    }

    @Test
    void returnsUserIdWithJwtWhenTotpIsNotEnabled() {
        UserDataBase user = user(42L, "alice", true, null);
        DeviceKeyCredential credential = credential("credential-1", user);
        DeviceKeyVerifyRequest request = request("credential-1", "alice");
        when(userRepository.findByUsername("alice")).thenReturn(user);
        when(deviceKeyRepository.findByCredentialIdAndUserId("credential-1", 42L)).thenReturn(Optional.of(credential));
        when(deviceKeyService.verifyAuthentication(request, user, credential)).thenReturn(9L);
        when(deviceKeyRepository.advanceCounter(eq("credential-1"), eq(42L), eq(9L), any(LocalDateTime.class)))
                .thenReturn(1);
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L)).thenReturn("jwt-token");

        VerifyDeviceKeyLoginUseCase.Result result = useCase.execute(request);

        assertThat(result.status()).isEqualTo(VerifyDeviceKeyLoginUseCase.Status.AUTHENTICATED);
        assertThat(result.data()).isEqualTo("42 jwt-token");
        verify(finalizeSignupAccount).ensureUserFinancialsReady(user, null);
        verify(jwtServicer).generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L);
    }

    private DeviceKeyVerifyRequest request(String credentialId, String username) {
        DeviceKeyVerifyRequest request = new DeviceKeyVerifyRequest();
        request.setCredentialId(credentialId);
        request.setUsername(username);
        return request;
    }

    private UserDataBase user(Long id, String username, boolean active, String totpSecret) {
        UserDataBase user = new UserDataBase();
        ReflectionTestUtils.setField(user, "id", id);
        user.setUsername(username);
        user.setIsActive(active);
        user.setTOTPSecret(totpSecret);
        return user;
    }

    private DeviceKeyCredential credential(String credentialId, UserDataBase user) {
        DeviceKeyCredential credential = new DeviceKeyCredential();
        credential.setCredentialId(credentialId);
        credential.setUser(user);
        return credential;
    }
}
