package com.kerosene.auth.application.orchestrator.recovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import com.kerosene.auth.application.infra.persistence.redis.contracts.RedisContract;
import com.kerosene.auth.application.port.out.AuthPasskeyGateway;
import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.auth.application.service.crypto.contracts.Cryptography;
import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import com.kerosene.auth.application.service.passkey.PasskeyService;
import com.kerosene.auth.application.service.recovery.RecoveryCredentialRotator;
import com.kerosene.auth.application.service.recovery.RecoveryCodeService;
import com.kerosene.auth.application.service.recovery.RecoverySecretProtector;
import com.kerosene.auth.application.service.recovery.RecoveryStateStore;
import com.kerosene.auth.application.service.recovery.start.EmergencyRecoveryStartContext;
import com.kerosene.auth.application.service.recovery.start.chain.EmergencyRecoveryStartChain;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPKeyGenerate;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.dto.EmergencyRecoveryFinishRequest;
import com.kerosene.auth.dto.EmergencyRecoveryFinishResponse;
import com.kerosene.auth.dto.EmergencyRecoveryStartRequest;
import com.kerosene.auth.dto.EmergencyRecoveryStartResponse;
import com.kerosene.auth.dto.EmergencyRecoveryState;
import com.kerosene.auth.model.entity.PasskeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.notification.model.UserNotificationPayload;
import com.kerosene.notification.service.NotificationService;
import com.kerosene.security.infra.VaultKeyProvider;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmergencyRecoveryUseCaseTest {

    private EmergencyRecoveryStartChain recoveryStartChain;
    private Hasher hasher;
    private TOTPKeyGenerate totpKeyGenerate;
    private TOTPVerifier totpVerifier;
    private PasskeyService passkeyService;
    private AuthUserGateway userGateway;
    private AuthPasskeyGateway passkeyGateway;
    private RedisContract redisContract;
    private Cryptography cryptography;
    private VaultKeyProvider vaultKeyProvider;
    private NotificationService notificationService;
    private RecoveryCodeService recoveryCodeService;
    private RecoveryStateStore stateStore;

    private EmergencyRecoveryUseCase useCase;

    @BeforeEach
    void setUp() throws Exception {
        recoveryStartChain = mock(EmergencyRecoveryStartChain.class);
        hasher = mock(Hasher.class);
        totpKeyGenerate = mock(TOTPKeyGenerate.class);
        totpVerifier = mock(TOTPVerifier.class);
        passkeyService = mock(PasskeyService.class);
        userGateway = mock(AuthUserGateway.class);
        passkeyGateway = mock(AuthPasskeyGateway.class);
        redisContract = mock(RedisContract.class);
        cryptography = mock(Cryptography.class);
        vaultKeyProvider = mock(VaultKeyProvider.class);
        notificationService = mock(NotificationService.class);
        recoveryCodeService = mock(RecoveryCodeService.class);

        AtomicInteger hashCounter = new AtomicInteger();
        when(hasher.hash(any(char[].class))).thenAnswer(invocation -> "hash-" + hashCounter.getAndIncrement());
        when(vaultKeyProvider.getMasterKey()).thenReturn(new SecretKeySpec(new byte[32], "AES"));

        RecoverySecretProtector secretProtector = new RecoverySecretProtector(
                hasher,
                totpKeyGenerate,
                cryptography,
                vaultKeyProvider);
        stateStore = new RecoveryStateStore(redisContract);
        RecoveryCredentialRotator credentialRotator = new RecoveryCredentialRotator(
                totpVerifier,
                passkeyService,
                userGateway,
                passkeyGateway,
                recoveryCodeService,
                notificationService,
                mock(com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy.class),
                mock(com.kerosene.auth.application.service.devicekey.DeviceKeyService.class),
                mock(com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository.class));

        useCase = new EmergencyRecoveryUseCase(
                recoveryStartChain,
                secretProtector,
                stateStore,
                credentialRotator,
                mock(com.kerosene.auth.application.service.recovery.RecoveryRateLimitService.class));

        ReflectionTestUtils.setField(useCase, "requiredRecoveryCodes", 3);
        ReflectionTestUtils.setField(stateStore, "recoverySessionTtlMinutes", 10L);
    }

    @Test
    void startShouldCreateRecoverySessionWhenChainSucceeds() throws Exception {
        EmergencyRecoveryStartRequest request = new EmergencyRecoveryStartRequest();
        request.setUsername("Alice");
        request.setNewPassphrase("legal winner thank year wave sausage worth useful legal winner thank yellow".toCharArray());

        EmergencyRecoveryStartContext context = new EmergencyRecoveryStartContext(request, "client-fingerprint");
        context.setNormalizedUsername("alice");
        context.setMatchedRecoveryCodeHashes(List.of("stored-1", "stored-2", "stored-3"));

        when(recoveryStartChain.handle(request, "client-fingerprint")).thenReturn(context);
        when(totpKeyGenerate.keyGenerator()).thenReturn("BASE32SECRET");
        when(cryptography.encrypt(any(byte[].class), any())).thenReturn("ciphertext".getBytes(StandardCharsets.UTF_8));

        EmergencyRecoveryStartResponse response = useCase.start(request, "client-fingerprint");

        assertNotNull(response.getRecoverySessionId());
        assertTrue(response.getOtpUri().contains("BASE32SECRET"));
        assertNotNull(response.getPasskeyChallenge());
        assertEquals(600L, response.getExpiresInSeconds());
        assertEquals(3, response.getRequiredRecoveryCodes());
        verify(redisContract).saveEmergencyRecoveryState(anyString(), any(EmergencyRecoveryState.class), eq(10L));
    }

    @Test
    void finishShouldRotateCredentialsAndReplacePasskeys() throws Exception {
        EmergencyRecoveryState state = new EmergencyRecoveryState();
        state.setSessionId("session-1");
        state.setUsername("alice");
        state.setHashedPassphrase("new-passphrase-hash");
        state.setEncryptedTotpSecret(Base64.getEncoder().encodeToString("encrypted".getBytes(StandardCharsets.UTF_8)));
        state.setPasskeyChallenge("challenge-hex");
        state.setMatchedBackupCodeHashes(List.of("stored-1", "stored-2", "stored-3"));

        UserDataBase user = new UserDataBase();
        user.setUsername("alice");
        user.setPassphrase("old-hash");
        user.setBackupCodes(new ArrayList<>(List.of("stored-1", "stored-2", "stored-3", "stored-4")));
        ReflectionTestUtils.setField(user, "id", 7L);

        EmergencyRecoveryFinishRequest request = new EmergencyRecoveryFinishRequest();
        request.setRecoverySessionId("session-1");
        request.setTotpCode("123456");
        request.setPublicKeyCose(Base64.getEncoder().encodeToString("public-key".getBytes(StandardCharsets.UTF_8)));
        request.setCredentialId(Base64.getEncoder().encodeToString("credential-id".getBytes(StandardCharsets.UTF_8)));
        request.setUserHandle(Base64.getEncoder().encodeToString("user-handle".getBytes(StandardCharsets.UTF_8)));
        request.setSignature("signature");
        request.setAuthData("authData");
        request.setClientDataJSON("clientData");
        request.setDeviceName("Recovery Device");

        RecoveryCodeService.GeneratedRecoveryCodes newCodes = new RecoveryCodeService.GeneratedRecoveryCodes(
                List.of("11111111", "22222222", "33333333", "44444444", "55555555",
                        "66666666", "77777777", "88888888", "99999999", "00000000"),
                List.of("hash-1", "hash-2", "hash-3", "hash-4", "hash-5",
                        "hash-6", "hash-7", "hash-8", "hash-9", "hash-10"));

        when(redisContract.getdelEmergencyRecoveryState("session-1")).thenReturn(state);
        when(userGateway.findByUsernameForUpdate("alice")).thenReturn(user);
        when(cryptography.decrypt(any(byte[].class), any())).thenReturn("BASE32SECRET".getBytes(StandardCharsets.UTF_8));
        when(totpVerifier.totpMatcher("BASE32SECRET", "123456")).thenReturn(true);
        when(passkeyService.verifyRegistrationSignature(eq("alice"), eq("challenge-hex"), eq("signature"), any(byte[].class),
                eq("authData"), eq("clientData"))).thenReturn(true);
        when(passkeyService.extractSignatureCount("authData")).thenReturn(1L);
        when(passkeyService.resolveRelyingPartyIdFromClientData("clientData")).thenReturn("localhost");
        when(passkeyService.extractOriginHostFromClientData("clientData")).thenReturn("localhost");
        when(passkeyGateway.findByUserId(7L)).thenReturn(List.of(new PasskeyCredential()));
        when(userGateway.save(any(UserDataBase.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(recoveryCodeService.generateNewBackupCodes()).thenReturn(newCodes);

        EmergencyRecoveryFinishResponse response = useCase.finish(request);

        assertEquals("alice", response.getUsername());
        assertEquals(10, response.getNewBackupCodes().size());
        assertEquals("new-passphrase-hash", user.getPassphrase());
        assertEquals("BASE32SECRET", user.getTOTPSecret());
        assertEquals(10, user.getBackupCodes().size());
        assertFalse(user.getBackupCodes().contains("stored-1"));
        verify(passkeyGateway).deleteAll(any());
        verify(passkeyGateway).save(any(PasskeyCredential.class));
        ArgumentCaptor<UserNotificationPayload> payloadCaptor =
                ArgumentCaptor.forClass(UserNotificationPayload.class);
        verify(notificationService).notifyUser(eq(7L), payloadCaptor.capture());
        assertEquals("security_recovery_completed", payloadCaptor.getValue().kind());
        assertEquals("Recuperação de segurança concluída", payloadCaptor.getValue().title());
    }
}
