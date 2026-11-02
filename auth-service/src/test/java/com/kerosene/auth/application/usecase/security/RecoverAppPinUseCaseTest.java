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
import com.kerosene.auth.dto.devicekey.DeviceKeyVerifyRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class RecoverAppPinUseCaseTest {
    private final UserServiceContract users = mock(UserServiceContract.class);
    private final LoginVerifier passwords = mock(LoginVerifier.class);
    private final LoginThrottlePolicy throttle = mock(LoginThrottlePolicy.class);
    private final DeviceKeyCredentialRepository credentials = mock(DeviceKeyCredentialRepository.class);
    private final DeviceKeyService deviceKeys = mock(DeviceKeyService.class);
    private final DeviceCredentialReplayGuard replayGuard = mock(DeviceCredentialReplayGuard.class);
    private final AppPinService pins = mock(AppPinService.class);
    private final RecoverAppPinUseCase useCase = new RecoverAppPinUseCase(
            users, passwords, throttle, credentials, deviceKeys, replayGuard, pins);
    private UserDataBase user;
    private DeviceKeyCredential credential;
    private RecoverAppPinRequestDTO request;

    @BeforeEach
    void setup() {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("42", null, "ROLE_USER"));
        user = new UserDataBase();
        org.springframework.test.util.ReflectionTestUtils.setField(user, "id", 42L);
        user.setUsername("alice");
        user.setIsActive(true);
        credential = new DeviceKeyCredential();
        credential.setUser(user);
        credential.setCredentialId("key-42");
        credential.setDeviceInstallId("install-42");
        request = new RecoverAppPinRequestDTO();
        request.setPassword("account password".toCharArray());
        request.setNewPin("0472");
        var proof = new DeviceKeyVerifyRequest();
        proof.setUsername("alice");
        proof.setCredentialId("key-42");
        proof.setDeviceInstallId("install-42");
        proof.setSignedPayload("canonical one-use authentication payload");
        proof.setSignature("device-signature");
        request.setDeviceKey(proof);
        when(users.buscarPorId(42L)).thenReturn(Optional.of(user));
    }

    @AfterEach
    void tearDown() { SecurityContextHolder.clearContext(); }

    private void validFactors() {
        when(passwords.matcherWithoutDevice(any())).thenReturn(user);
        when(credentials.findByCredentialIdAndUserId("key-42", 42L)).thenReturn(Optional.of(credential));
        when(deviceKeys.verifyAuthentication(request.getDeviceKey(), user, credential)).thenReturn(8L);
        when(credentials.advanceCounter(eq("key-42"), eq(42L), eq(8L), any())).thenReturn(1);
    }

    @Test
    void requiresBothFreshFactorsThenAdvancesCounterBeforePinMutationAndWipesPassword() {
        validFactors();
        var status = new AppPinStatusDTO(true, true, false, 0, 5, 5, 4, 8, false, true, null, null, null);
        when(passwords.matcherWithoutDevice(any())).thenAnswer(invocation -> {
            var input = invocation.getArgument(0, com.kerosene.auth.dto.contracts.UserDTOContract.class);
            assertThat(input.getUsername()).isEqualTo("alice");
            assertThat(input.getPassphrase()).containsExactly("account password".toCharArray());
            return user;
        });
        when(pins.recoverWithVerifiedAccountFactors(user, "device-42", "0472")).thenReturn(status);

        assertThat(useCase.execute("device-42", request)).isSameAs(status);
        var ordered = inOrder(passwords, deviceKeys, credentials, pins);
        ordered.verify(passwords).matcherWithoutDevice(any());
        ordered.verify(credentials).findByCredentialIdAndUserId("key-42", 42L);
        ordered.verify(deviceKeys).verifyAuthentication(request.getDeviceKey(), user, credential);
        ordered.verify(credentials).advanceCounter(eq("key-42"), eq(42L), eq(8L), any());
        ordered.verify(pins).recoverWithVerifiedAccountFactors(user, "device-42", "0472");
        assertThat(new String(request.getPassword())).isEqualTo("\0".repeat("account password".length()));
    }

    @Test
    void refusesMissingBearerSessionBeforeInspectingOrMutatingFactors() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.InvalidCredentials.class);
        verifyNoInteractions(passwords, credentials, deviceKeys, pins);
        assertThat(request.getPassword()).containsOnly('\0');
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"123", "12345", "12345678", "12a4", " 1234", "１２３４"})
    void rejectsAnythingOtherThanFourAsciiDigitsBeforeConsumingAnyProof(String pin) {
        request.setNewPin(pin);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(passwords, credentials, deviceKeys, pins);
    }

    @Test
    void rejectsWrongPasswordWithoutConsumingDeviceChallengeOrInvalidatingSession() {
        when(passwords.matcherWithoutDevice(any())).thenThrow(new AuthExceptions.InvalidCredentials("wrong"));
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOfSatisfying(AuthExceptions.StructuredAuthException.class,
                        error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        verify(throttle).recordLoginFailure("alice");
        verifyNoInteractions(credentials, deviceKeys, pins);
        assertThat(request.getPassword()).containsOnly('\0');
    }

    @Test
    void rejectsPasswordVerificationForDifferentAccount() {
        var foreign = new UserDataBase();
        org.springframework.test.util.ReflectionTestUtils.setField(foreign, "id", 99L);
        when(passwords.matcherWithoutDevice(any())).thenReturn(foreign);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(credentials, deviceKeys, pins);
    }

    @Test
    void requiresRegisteredCredentialForAuthenticatedOwner() {
        when(passwords.matcherWithoutDevice(any())).thenReturn(user);
        when(credentials.findByCredentialIdAndUserId("key-42", 42L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(deviceKeys, pins);
    }

    @Test
    void rejectsMissingPasswordEvenWithDeviceProof() {
        request.setPassword(null);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(passwords, credentials, deviceKeys, pins);
    }

    @Test
    void rejectsMissingDeviceProofEvenWithPassword() {
        request.setDeviceKey(null);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(passwords, credentials, deviceKeys, pins);
    }

    @ParameterizedTest
    @ValueSource(strings = {"BLOCKED", "REVOKED", "SUSPENDED"})
    void rejectsInactiveDeviceCredentialsBeforeSignatureVerification(String status) {
        validFactors();
        credential.setStatus(status);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(pins);
        verify(deviceKeys, never()).verifyAuthentication(any(), any(), any());
    }

    @Test
    void rejectsCredentialWithRevocationTimestampEvenIfStatusStillActive() {
        validFactors();
        credential.setRevokedAt(LocalDateTime.now());
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(pins);
        verify(deviceKeys, never()).verifyAuthentication(any(), any(), any());
    }

    @Test
    void rejectsMismatchedInstallationExpiredChallengeOrInvalidSignature() {
        validFactors();
        when(deviceKeys.verifyAuthentication(any(), any(), any()))
                .thenThrow(new DeviceKeyProtocolException("assertion rejected"));
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verify(credentials, never()).advanceCounter(any(), any(), anyLong(), any());
        verifyNoInteractions(pins);
    }

    @Test
    void failedCounterCompareAndSetCannotRecoverPin() {
        validFactors();
        when(credentials.advanceCounter(eq("key-42"), eq(42L), eq(8L), any())).thenReturn(0);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(pins);
    }

    @Test
    void rejectsReplayLockedCredential() {
        validFactors();
        when(replayGuard.isLocked(eq(42L), any())).thenReturn(true);
        assertThatThrownBy(() -> useCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verifyNoInteractions(pins);
        verify(deviceKeys, never()).verifyAuthentication(any(), any(), any());
    }

    @Test
    void databaseCounterAndPinWriteRollbackTogetherWhenPinPersistenceFails() {
        validFactors();
        var source = new org.springframework.jdbc.datasource.DriverManagerDataSource(
                "jdbc:h2:mem:pin_recovery_" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        var sql = new org.springframework.jdbc.core.JdbcTemplate(source);
        sql.execute("create table recovery (id integer primary key, device_counter bigint, pin_hash varchar(50))");
        sql.update("insert into recovery values (1, 7, 'old-hash')");
        when(credentials.advanceCounter(eq("key-42"), eq(42L), eq(8L), any())).thenAnswer(invocation ->
                sql.update("update recovery set device_counter=8 where id=1 and device_counter<8"));
        when(pins.recoverWithVerifiedAccountFactors(user, "device-42", "0472")).thenAnswer(invocation -> {
            sql.update("update recovery set pin_hash='new-hash' where id=1");
            throw new IllegalStateException("storage failed");
        });
        var proxy = new org.springframework.aop.framework.ProxyFactory(useCase);
        proxy.setProxyTargetClass(true);
        proxy.addAdvice(new org.springframework.transaction.interceptor.TransactionInterceptor(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(source),
                new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()));
        var transactional = (RecoverAppPinUseCase) proxy.getProxy();

        assertThatThrownBy(() -> transactional.execute("device-42", request))
                .isInstanceOf(IllegalStateException.class);
        assertThat(sql.queryForObject("select device_counter from recovery where id=1", Long.class)).isEqualTo(7L);
        assertThat(sql.queryForObject("select pin_hash from recovery where id=1", String.class)).isEqualTo("old-hash");
        sql.execute("shutdown");
    }

    private RecoverAppPinUseCase withRealSignedDeviceAssertion(boolean invalidSignature) throws Exception {
        validFactors();
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var redis = mock(com.kerosene.auth.application.service.cache.contracts.RedisServicer.class);
        var store = new java.util.concurrent.ConcurrentHashMap<String, String>();
        doAnswer(invocation -> {
            store.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(redis).setValue(anyString(), anyString(), anyLong());
        when(redis.getAndDeleteValue(anyString())).thenAnswer(invocation -> store.remove(invocation.getArgument(0)));
        var realDeviceKeys = new DeviceKeyService(redis, mapper, "recovery-fixture.onion", 90);
        var challenge = realDeviceKeys.startAuthenticationChallenge(user);
        var pair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] publicKey = pair.getPublic().getEncoded();
        credential.setPublicKeyEd25519(java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.util.Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length)));
        var payload = new java.util.TreeMap<String, Object>();
        payload.put("challenge", challenge.challenge());
        payload.put("challengeId", challenge.challengeId());
        payload.put("counter", 8L);
        payload.put("credentialId", "key-42");
        payload.put("deviceInstallId", "install-42");
        payload.put("issuedAtEpochSeconds", java.time.Instant.now().getEpochSecond());
        payload.put("onionServiceId", challenge.onionServiceId());
        payload.put("type", "AUTH_DEVICE_KEY");
        payload.put("username", "alice");
        payload.put("version", 1);
        String canonical = mapper.writeValueAsString(payload);
        var signature = java.security.Signature.getInstance("Ed25519");
        signature.initSign(pair.getPrivate());
        signature.update(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        if (invalidSignature) signed[0] ^= 1;
        request.getDeviceKey().setSignedPayload(canonical);
        request.getDeviceKey().setSignature(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signed));
        return new RecoverAppPinUseCase(users, passwords, throttle, credentials, realDeviceKeys, replayGuard, pins);
    }

    @Test
    void actualEd25519ProofAuthorizesRecoveryOnceAndCannotBeReplayed() throws Exception {
        var realProofUseCase = withRealSignedDeviceAssertion(false);
        realProofUseCase.execute("device-42", request);
        request.setPassword("account password".toCharArray());
        assertThatThrownBy(() -> realProofUseCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verify(pins, times(1)).recoverWithVerifiedAccountFactors(user, "device-42", "0472");
    }

    @Test
    void actualInvalidEd25519SignatureCannotChangePinOrAdvanceCounter() throws Exception {
        var realProofUseCase = withRealSignedDeviceAssertion(true);
        assertThatThrownBy(() -> realProofUseCase.execute("device-42", request))
                .isInstanceOf(AuthExceptions.StructuredAuthException.class);
        verify(credentials, never()).advanceCounter(any(), any(), anyLong(), any());
        verifyNoInteractions(pins);
    }
}
