package com.kerosene.auth.application.orchestrator.recovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.redis.contracts.RedisContract;
import com.kerosene.auth.application.port.out.AuthPasskeyGateway;
import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy;
import com.kerosene.auth.application.service.devicekey.DeviceKeyProtocolException;
import com.kerosene.auth.application.service.devicekey.DeviceKeyService;
import com.kerosene.auth.application.service.passkey.PasskeyService;
import com.kerosene.auth.application.service.recovery.*;
import com.kerosene.auth.application.service.recovery.start.chain.EmergencyRecoveryStartChain;
import com.kerosene.auth.application.service.crypto.contracts.Cryptography;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPKeyGenerate;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.dto.*;
import com.kerosene.auth.dto.devicebinding.DeviceAlreadyBoundDTO;
import com.kerosene.auth.dto.devicekey.DeviceKeyChallengeResponse;
import com.kerosene.auth.dto.devicekey.DeviceKeyRegistrationRequest;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.notification.service.NotificationService;
import com.kerosene.security.infra.VaultKeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CanonicalDeviceKeyRecoveryTest {
    private final AuthUserGateway users = mock(AuthUserGateway.class);
    private final AuthPasskeyGateway passkeys = mock(AuthPasskeyGateway.class);
    private final DeviceKeyCredentialRepository keys = mock(DeviceKeyCredentialRepository.class);
    private final DeviceBindingPolicy binding = mock(DeviceBindingPolicy.class);
    private final TOTPVerifier totp = mock(TOTPVerifier.class);
    private final NotificationService notifications = mock(NotificationService.class);
    private final RedisContract sessions = mock(RedisContract.class);
    private final Map<String,EmergencyRecoveryState> state = new HashMap<>();
    private final ObjectMapper json = new ObjectMapper();
    private UserDataBase user;
    private EmergencyRecoveryState recovery;
    private DeviceKeyCredential oldKey;
    private EmergencyRecoveryUseCase useCase;

    @BeforeEach
    void setup() throws Exception {
        user = new UserDataBase();
        ReflectionTestUtils.setField(user,"id",42L);
        user.setUsername("public_fixture");
        user.setPassphrase("OLD_PUBLIC_FIXTURE_HASH");
        user.setBackupCodes(new ArrayList<>(List.of("hash-a","hash-b","hash-c","hash-d")));
        when(users.findByUsername("public_fixture")).thenReturn(user);
        when(users.findByUsernameForUpdate("public_fixture")).thenReturn(user);
        when(users.save(any())).thenAnswer(i->i.getArgument(0));
        when(totp.totpMatcher("JBSWY3DPEHPK3PXP","123456")).thenReturn(true);
        recovery = new EmergencyRecoveryState();
        recovery.setSessionId("fixture-session"); recovery.setUsername("public_fixture");
        recovery.setMatchedBackupCodeHashes(List.of("hash-a","hash-b","hash-c"));
        recovery.setEncryptedTotpSecret(Base64.getEncoder().encodeToString("PUBLIC_CIPHERTEXT".getBytes(StandardCharsets.UTF_8)));
        recovery.setHashedPassphrase("NEW_PUBLIC_FIXTURE_HASH");
        state.put(recovery.getSessionId(),recovery);
        when(sessions.findEmergencyRecoveryState(anyString())).thenAnswer(i->state.get(i.getArgument(0)));
        when(sessions.getdelEmergencyRecoveryState(anyString())).thenAnswer(i->state.remove(i.getArgument(0)));
        AtomicLong attempts = new AtomicLong();
        when(sessions.incrementWithExpire(anyString(),anyLong())).thenAnswer(i->attempts.incrementAndGet());
        var rate = new RecoveryRateLimitService(sessions);
        ReflectionTestUtils.setField(rate,"clientWindowSeconds",600L);
        ReflectionTestUtils.setField(rate,"clientMaxAttempts",6L);
        var redis = mock(RedisServicer.class);
        var challengeStore = new ConcurrentHashMap<String,String>();
        doAnswer(i->{challengeStore.put(i.getArgument(0),i.getArgument(1));return null;})
                .when(redis).setValue(anyString(),anyString(),anyLong());
        when(redis.getAndDeleteValue(anyString())).thenAnswer(i->challengeStore.remove(i.getArgument(0)));
        var crypto = mock(Cryptography.class);
        when(crypto.decrypt(any(),any())).thenAnswer(i -> "JBSWY3DPEHPK3PXP".getBytes(StandardCharsets.UTF_8));
        var vault = mock(VaultKeyProvider.class);
        when(vault.getMasterKey()).thenReturn(new SecretKeySpec(new byte[32],"AES"));
        var secrets = new RecoverySecretProtector(mock(Hasher.class),mock(TOTPKeyGenerate.class),crypto,vault);
        var codes = mock(RecoveryCodeService.class);
        when(codes.generateNewBackupCodes()).thenReturn(new RecoveryCodeService.GeneratedRecoveryCodes(
                List.of("01010101","02020202","03030303","04040404","05050505","06060606","07070707","08080808","09090909","10101010"),
                List.of("new-a","new-b","new-c","new-d","new-e","new-f","new-g","new-h","new-i","new-j")));
        oldKey = new DeviceKeyCredential();oldKey.setUser(user);oldKey.setStatus("ACTIVE");
        when(keys.findByUserId(42L)).thenReturn(List.of(oldKey));
        when(keys.save(any())).thenAnswer(i->i.getArgument(0));
        var rotator = new RecoveryCredentialRotator(totp,mock(PasskeyService.class),users,passkeys,codes,
                notifications,binding,new DeviceKeyService(redis,json,"fixture.onion",90L),keys);
        useCase = new EmergencyRecoveryUseCase(mock(EmergencyRecoveryStartChain.class),secrets,
                new RecoveryStateStore(sessions),rotator,rate);
    }

    private DeviceKeyChallengeResponse challenge(String code) {
        var request = new EmergencyRecoveryDeviceKeyChallengeRequest();
        request.setRecoverySessionId(recovery.getSessionId());request.setTotpCode(code);
        return useCase.prepareDeviceKeyChallenge(request);
    }

    private EmergencyRecoveryFinishRequest signed(DeviceKeyChallengeResponse challenge,String signedSession) throws Exception {
        var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded,encoded.length-32,encoded.length);
        var payload = new TreeMap<String,Object>();
        payload.put("algorithm","Ed25519");payload.put("challenge",challenge.challenge());
        payload.put("challengeId",challenge.challengeId());payload.put("counter",1L);
        payload.put("credentialId","PUBLIC_FIXTURE_CREDENTIAL");payload.put("deviceInstallId","PUBLIC_FIXTURE_INSTALL");
        payload.put("issuedAtEpochSeconds",Instant.now().getEpochSecond());payload.put("onionServiceId",challenge.onionServiceId());
        payload.put("publicKeySha256",url(MessageDigest.getInstance("SHA-256").digest(raw)));
        payload.put("sessionId",signedSession);payload.put("type","REGISTER_DEVICE_KEY");
        payload.put("username","public_fixture");payload.put("version",1);
        String text=json.writeValueAsString(payload);
        var signer=Signature.getInstance("Ed25519");signer.initSign(pair.getPrivate());
        signer.update(text.getBytes(StandardCharsets.UTF_8));
        var proof=new DeviceKeyRegistrationRequest();proof.setCredentialId("PUBLIC_FIXTURE_CREDENTIAL");
        proof.setPublicKey(url(raw));proof.setPublicKeySha256(payload.get("publicKeySha256").toString());
        proof.setDeviceInstallId("PUBLIC_FIXTURE_INSTALL");proof.setDeviceName("Public Fixture Device");
        proof.setKeyStorage("SECURE_STORAGE");proof.setPlatform("android");
        proof.setSignedPayload(text);proof.setSignature(url(signer.sign()));
        var request=new EmergencyRecoveryFinishRequest();request.setRecoverySessionId(recovery.getSessionId());
        request.setTotpCode("123456");request.setDeviceKeyRegistration(proof);
        return request;
    }
    private String url(byte[] bytes) {return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}

    @Test
    void canonicalEd25519ProofRotatesCredentialsRevokesOldKeysAndAcknowledgesTheNewKey() throws Exception {
        var response=useCase.finish(signed(challenge("123456"),recovery.getSessionId()));
        assertThat(response.getDeviceKeyCredentialId()).isEqualTo("PUBLIC_FIXTURE_CREDENTIAL");
        assertThat(response.getNewBackupCodes()).hasSize(10);
        assertThat(user.getPassphrase()).isEqualTo("NEW_PUBLIC_FIXTURE_HASH");
        assertThat(oldKey.getStatus()).isEqualTo("REVOKED");assertThat(oldKey.getRevokedAt()).isNotNull();
        var saved=ArgumentCaptor.forClass(DeviceKeyCredential.class);verify(keys).save(saved.capture());
        assertThat(saved.getValue().getCredentialId()).isEqualTo(response.getDeviceKeyCredentialId());
        assertThat(saved.getValue().getStatus()).isEqualTo("ACTIVE");
        verify(users).findByUsernameForUpdate("public_fixture");
        verify(binding).ensureDeviceAvailableForBind("PUBLIC_FIXTURE_INSTALL",42L,false);
        verify(passkeys,never()).save(any());
        verify(notifications).notifyUser(eq(42L),any());
        assertThat(state).isEmpty();
    }

    @Test
    void wrongAuthenticatorCannotMintAnEnrollmentChallenge() {
        assertThatThrownBy(()->challenge("654321")).isInstanceOf(AuthExceptions.RecoveryRejectedException.class);
        assertThat(state).containsKey(recovery.getSessionId());
        verify(users,never()).save(any());verify(keys,never()).save(any());
    }

    @Test
    void tooManyAuthenticatorGuessesAreBlockedEvenWithAProvenSession() {
        for(int i=0;i<6;i++) assertThatThrownBy(()->challenge("654321")).isInstanceOf(AuthExceptions.RecoveryRejectedException.class);
        assertThatThrownBy(()->challenge("123456")).isInstanceOf(AuthExceptions.RecoveryRateLimitedException.class);
    }

    @Test
    void wrongSessionInAnOtherwiseValidSignatureNeverMutatesCredentials() throws Exception {
        var request=signed(challenge("123456"),"foreign-session");
        assertThatThrownBy(()->useCase.finish(request)).isInstanceOf(DeviceKeyProtocolException.class);
        assertThat(user.getPassphrase()).isEqualTo("OLD_PUBLIC_FIXTURE_HASH");
        verify(users,never()).save(any());verify(keys,never()).save(any());
        assertThat(oldKey.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void invalidSignatureNeverMutatesCredentialsAndCannotReuseTheConsumedSession() throws Exception {
        var request=signed(challenge("123456"),recovery.getSessionId());
        byte[] signature=Base64.getUrlDecoder().decode(request.getDeviceKeyRegistration().getSignature());signature[0]^=1;
        request.getDeviceKeyRegistration().setSignature(url(signature));
        assertThatThrownBy(()->useCase.finish(request)).isInstanceOf(DeviceKeyProtocolException.class);
        assertThatThrownBy(()->useCase.finish(request)).isInstanceOf(AuthExceptions.RecoverySessionExpiredException.class);
        verify(users,never()).save(any());verify(keys,never()).save(any());
    }

    @Test
    void twoStartedSessionsCannotBothUseRecoveryCodesAlreadyReplaced() throws Exception {
        var another=new EmergencyRecoveryState();another.setSessionId("second-session");another.setUsername(recovery.getUsername());
        another.setMatchedBackupCodeHashes(recovery.getMatchedBackupCodeHashes());another.setEncryptedTotpSecret(recovery.getEncryptedTotpSecret());
        state.put(another.getSessionId(),another);
        useCase.finish(signed(challenge("123456"),recovery.getSessionId()));
        recovery=another;
        assertThatThrownBy(()->challenge("123456")).isInstanceOf(AuthExceptions.RecoveryRejectedException.class);
        verify(users,times(1)).save(any());
    }

    @Test
    void emptyOrDuplicateCodeAuthorityCannotPrepareRecovery() {
        recovery.setMatchedBackupCodeHashes(List.of());
        assertThatThrownBy(()->challenge("123456")).isInstanceOf(AuthExceptions.RecoveryRejectedException.class);
        recovery.setMatchedBackupCodeHashes(List.of("hash-a","hash-a","hash-a"));
        assertThatThrownBy(()->challenge("123456")).isInstanceOf(AuthExceptions.RecoveryRejectedException.class);
    }

    @Test
    void canonicalAndLegacyProofFieldsCannotBeMixed() throws Exception {
        var request=signed(challenge("123456"),recovery.getSessionId());request.setSignature("legacy-proof");
        assertThatThrownBy(()->useCase.finish(request)).isInstanceOf(IllegalArgumentException.class);
        assertThat(state).containsKey(recovery.getSessionId());
        verify(users,never()).findByUsernameForUpdate(anyString());
    }
}
