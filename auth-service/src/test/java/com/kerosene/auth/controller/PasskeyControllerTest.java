package com.kerosene.auth.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.kerosene.platform.exception.GlobalExceptionHandler;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import com.kerosene.auth.application.infra.persistence.jpa.PasskeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.PasskeyVerificationProjection;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.auth.application.orchestrator.signup.port.SignupStateStore;
import com.kerosene.auth.application.service.passkey.PasskeyInventoryService;
import com.kerosene.auth.application.service.passkey.PasskeyService;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.orchestrator.login.StartLogin;
import com.kerosene.auth.application.orchestrator.passkey.PasskeyOrchestrator;
import com.kerosene.auth.application.usecase.passkey.GetPasskeyInventoryUseCase;
import com.kerosene.auth.application.usecase.passkey.UpdatePasskeyDeviceStatusUseCase;
import com.kerosene.auth.dto.PasskeyInventoryDTO;
import com.kerosene.auth.dto.SignupState;
import com.kerosene.auth.dto.passkey.PasskeyRegistrationRequest;
import com.kerosene.auth.dto.passkey.PasskeyVerifyRequest;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.common.exception.ErrorCodes;
import com.kerosene.common.exception.FinancialProviderUnavailableException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

class PasskeyControllerTest {

    private PasskeyService passkeyService;
    private PasskeyCredentialRepository passkeyCredentialRepository;
    private UserRepository userRepository;
    private PasskeyInventoryService passkeyInventoryService;
    private SignupStateStore signupStateStore;
    private FinalizeSignupAccount finalizeSignupAccount;
    private JwtServicer jwtServicer;
    private RedisServicer redisService;
    private GetPasskeyInventoryUseCase getPasskeyInventoryUseCase;
    private UpdatePasskeyDeviceStatusUseCase updatePasskeyDeviceStatusUseCase;
    private PasskeyController controller;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        passkeyService = mock(PasskeyService.class);
        passkeyCredentialRepository = mock(PasskeyCredentialRepository.class);
        userRepository = mock(UserRepository.class);
        passkeyInventoryService = mock(PasskeyInventoryService.class);
        signupStateStore = mock(SignupStateStore.class);
        finalizeSignupAccount = mock(FinalizeSignupAccount.class);
        jwtServicer = mock(JwtServicer.class);
        redisService = mock(RedisServicer.class);
        getPasskeyInventoryUseCase = mock(GetPasskeyInventoryUseCase.class);
        updatePasskeyDeviceStatusUseCase = mock(UpdatePasskeyDeviceStatusUseCase.class);

        PasskeyOrchestrator passkeyOrchestrator = new PasskeyOrchestrator(
                passkeyService,
                passkeyCredentialRepository,
                userRepository,
                jwtServicer,
                signupStateStore,
                passkeyInventoryService,
                finalizeSignupAccount,
                redisService,
                mock(com.kerosene.auth.application.service.devicebinding.DeviceBindingPolicy.class),
                mock(com.kerosene.auth.application.service.devicebinding.DeviceCredentialReplayGuard.class),
                mock(org.springframework.transaction.PlatformTransactionManager.class));
        controller = new PasskeyController(
                passkeyService,
                jwtServicer,
                signupStateStore,
                finalizeSignupAccount,
                redisService,
                passkeyOrchestrator,
                getPasskeyInventoryUseCase,
                updatePasskeyDeviceStatusUseCase);
    }

    @Test
    void passkeyChallengeNormalizesUsernameLikePasswordLogin() {
        when(passkeyService.generateChallenge("manobrow")).thenReturn("challenge-hex");

        ResponseEntity<ApiResponse<String>> response = controller.getChallenge("  ManoBrow  ");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("challenge-hex", response.getBody().getData());
        verify(passkeyService).generateChallenge("manobrow");
    }

    @Test
    void passkeyVerifyResolvesUserByCredentialIdWhenUsernameIsMissing() {
        byte[] credentialId = new byte[] { 1, 2, 3 };
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");
        user.setIsActive(true);

        PasskeyVerificationProjection credential = new PasskeyVerificationProjection(
                credentialId,
                new byte[32],
                0L,
                "ACTIVE",
                "localhost",
                "localhost",
                42L,
                "alice",
                true);

        PasskeyVerifyRequest request = new PasskeyVerifyRequest();
        request.setCredentialId(Base64.getEncoder().encodeToString(credentialId));
        request.setSignature("signature");
        request.setAuthData("auth-data");
        request.setClientDataJSON("client-data");

        when(passkeyCredentialRepository.findVerificationByCredentialId(any(byte[].class)))
                .thenReturn(Optional.of(credential));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user));
        when(passkeyInventoryService.isKnownIncompatibleForCurrentLogin("localhost", "localhost")).thenReturn(false);
        when(passkeyService.isClientDataOriginAllowed("client-data")).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"),
                eq("challenge-hex"),
                eq("signature"),
                any(byte[].class),
                eq("auth-data"),
                eq("client-data"))).thenReturn(new PasskeyService.PasskeyVerificationResult(true, 1L));
        when(passkeyCredentialRepository.advanceSignatureCount(any(byte[].class), anyLong(), anyLong()))
                .thenReturn(1);
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L)).thenReturn("jwt.token.value");

        ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("42 jwt.token.value", response.getBody().getData());
        verify(userRepository, never()).findByUsername(any());
        verify(passkeyCredentialRepository).findVerificationByCredentialId(any(byte[].class));
        verify(passkeyService).consumeChallengeFromRedis("alice");
    }

    @Test
    void passkeyVerifyLogsSafeFailureDiagnosticsWhenCredentialIsNotFound() {
        byte[] credentialId = "raw-credential-secret".getBytes(StandardCharsets.UTF_8);
        String credentialIdBase64 = Base64.getEncoder().encodeToString(credentialId);
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");
        user.setIsActive(true);

        PasskeyVerifyRequest request = new PasskeyVerifyRequest();
        request.setUsername("  Alice  ");
        request.setCredentialId(credentialIdBase64);
        request.setSignature("raw-signature-secret");
        request.setAuthData("raw-authdata-secret");
        request.setClientDataJSON("raw-clientdata-secret");

        when(userRepository.findByUsername("alice")).thenReturn(user);
        when(passkeyCredentialRepository.findVerificationByCredentialIdAndUserId(any(byte[].class), eq(42L)))
                .thenReturn(Optional.empty());

        ListAppender<ILoggingEvent> appender = attachPasskeyOrchestratorLogAppender();
        try {
            ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND, response.getBody().getErrorCode());

            String logs = formattedMessages(appender);
            assertTrue(logs.contains("event=AUTH_PASSKEY_VERIFY_FAILED"));
            assertTrue(logs.contains("failureBranch=credential_not_found"));
            assertTrue(logs.contains("errorCode=" + ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND));
            assertTrue(logs.contains("usernamePresent=true"));
            assertTrue(logs.contains("credentialIdPresent=true"));
            assertTrue(logs.contains("credentialRef=sha256:"));
            assertTrue(hasAuthMarker(appender));

            assertFalse(logs.contains("alice"));
            assertFalse(logs.contains(credentialIdBase64));
            assertFalse(logs.contains("raw-credential-secret"));
            assertFalse(logs.contains("raw-signature-secret"));
            assertFalse(logs.contains("raw-authdata-secret"));
            assertFalse(logs.contains("raw-clientdata-secret"));
        } finally {
            detachPasskeyOrchestratorLogAppender(appender);
        }
    }

    @Test
    void passkeyVerifyLogsSafeFailureDiagnosticsWhenAssertionFails() {
        byte[] credentialId = "raw-credential-secret".getBytes(StandardCharsets.UTF_8);
        UserDataBase user = activeUser("alice", 42L);
        PasskeyVerificationProjection credential = activeCredential(credentialId, 7L);
        PasskeyVerifyRequest request = verifyRequest("  Alice  ", credentialId);

        when(userRepository.findByUsername("alice")).thenReturn(user);
        when(passkeyCredentialRepository.findVerificationByCredentialIdAndUserId(any(byte[].class), eq(42L)))
                .thenReturn(Optional.of(credential));
        when(passkeyInventoryService.isKnownIncompatibleForCurrentLogin("kerosene-device", "localhost"))
                .thenReturn(false);
        when(passkeyService.isClientDataOriginAllowed("raw-clientdata-secret")).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"),
                eq("challenge-hex"),
                eq("raw-signature-secret"),
                any(byte[].class),
                eq("raw-authdata-secret"),
                eq("raw-clientdata-secret"))).thenReturn(new PasskeyService.PasskeyVerificationResult(false, -1L));
        when(passkeyService.resolveCurrentRelyingPartyId()).thenReturn("kerosene-device");
        when(passkeyService.resolveCurrentRequestHost()).thenReturn("localhost");

        ListAppender<ILoggingEvent> appender = attachPasskeyOrchestratorLogAppender();
        try {
            ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED, response.getBody().getErrorCode());

            String logs = formattedMessages(appender);
            assertTrue(logs.contains("event=AUTH_PASSKEY_VERIFY_FAILED"));
            assertTrue(logs.contains("failureBranch=assertion_failed"));
            assertTrue(logs.contains("errorCode=" + ErrorCodes.AUTH_PASSKEY_ASSERTION_FAILED));
            assertTrue(logs.contains("savedRpIdRef=sha256:"));
            assertTrue(logs.contains("savedOriginHost=localhost"));
            assertTrue(logs.contains("currentRpId=kerosene-device"));
            assertTrue(logs.contains("currentHost=localhost"));
            assertTrue(hasAuthMarker(appender));
            assertSafePasskeyFailureLog(logs, request, credentialId);
        } finally {
            detachPasskeyOrchestratorLogAppender(appender);
        }
    }

    @Test
    void passkeyVerifyLogsSafeFailureDiagnosticsWhenCounterDoesNotAdvance() {
        byte[] credentialId = "raw-credential-secret".getBytes(StandardCharsets.UTF_8);
        UserDataBase user = activeUser("alice", 42L);
        PasskeyVerificationProjection credential = activeCredential(credentialId, 7L);
        PasskeyVerifyRequest request = verifyRequest("  Alice  ", credentialId);

        when(userRepository.findByUsername("alice")).thenReturn(user);
        when(passkeyCredentialRepository.findVerificationByCredentialIdAndUserId(any(byte[].class), eq(42L)))
                .thenReturn(Optional.of(credential));
        when(passkeyInventoryService.isKnownIncompatibleForCurrentLogin("kerosene-device", "localhost"))
                .thenReturn(false);
        when(passkeyService.isClientDataOriginAllowed("raw-clientdata-secret")).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"),
                eq("challenge-hex"),
                eq("raw-signature-secret"),
                any(byte[].class),
                eq("raw-authdata-secret"),
                eq("raw-clientdata-secret"))).thenReturn(new PasskeyService.PasskeyVerificationResult(true, 7L));
        when(passkeyService.resolveCurrentRelyingPartyId()).thenReturn("kerosene-device");
        when(passkeyService.resolveCurrentRequestHost()).thenReturn("localhost");

        ListAppender<ILoggingEvent> appender = attachPasskeyOrchestratorLogAppender();
        try {
            ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(ErrorCodes.AUTH_PASSKEY_REPLAY, response.getBody().getErrorCode());

            String logs = formattedMessages(appender);
            assertTrue(logs.contains("event=AUTH_PASSKEY_VERIFY_FAILED"));
            assertTrue(logs.contains("failureBranch=replay_counter_not_advanced"));
            assertTrue(logs.contains("errorCode=" + ErrorCodes.AUTH_PASSKEY_REPLAY));
            assertTrue(logs.contains("storedSignatureCount=7"));
            assertTrue(logs.contains("receivedSignatureCount=7"));
            assertTrue(hasAuthMarker(appender));
            assertSafePasskeyFailureLog(logs, request, credentialId);
        } finally {
            detachPasskeyOrchestratorLogAppender(appender);
        }
    }

    @Test
    void passkeyVerifyRejectsInactiveAccount() {
        byte[] credentialId = new byte[] { 1, 2, 3 };
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");
        user.setIsActive(false); // Inactive

        PasskeyVerificationProjection credential = new PasskeyVerificationProjection(
                credentialId, new byte[32], 0L, "ACTIVE", "localhost", "localhost", 42L, "alice", true);

        PasskeyVerifyRequest request = new PasskeyVerifyRequest();
        request.setCredentialId(Base64.getEncoder().encodeToString(credentialId));

        when(passkeyCredentialRepository.findVerificationByCredentialId(any(byte[].class)))
                .thenReturn(Optional.of(credential));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user));
        when(passkeyInventoryService.isKnownIncompatibleForCurrentLogin("localhost", "localhost")).thenReturn(false);
        when(passkeyService.isClientDataOriginAllowed(any())).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"), eq("challenge-hex"), any(), any(byte[].class), any(), any()))
                .thenReturn(new PasskeyService.PasskeyVerificationResult(true, 1L));
        when(passkeyCredentialRepository.advanceSignatureCount(any(byte[].class), anyLong(), anyLong())).thenReturn(1);

        ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(ErrorCodes.AUTH_INVALID_CREDENTIALS, response.getBody().getErrorCode());
        assertEquals("Account is inactive", response.getBody().getMessage());
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(any(Long.class), org.mockito.ArgumentMatchers.anyCollection(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void passkeyVerifyReturns503WithoutMisclassifyingFinancialOutages() throws Exception {
        assertPasskeyDependencyUnavailable(
                new FinancialProviderUnavailableException("private-custody-endpoint"),
                "ERR_KFE_RAIL_PROVIDER_UNAVAILABLE");
    }

    @Test
    void passkeyVerifyReturns503WithoutExposingVaultDiagnostics() throws Exception {
        assertPasskeyDependencyUnavailable(
                new FinalizeSignupAccount.VaultNotReadyException("private-vault-endpoint"),
                "ERR_VAULT_NOT_READY");
    }

    private void assertPasskeyDependencyUnavailable(RuntimeException outage, String errorCode) throws Exception {
        byte[] credentialId = new byte[] { 1, 2, 3 };
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");
        user.setIsActive(true);
        var credential = new PasskeyVerificationProjection(
                credentialId, new byte[32], 0L, "ACTIVE", "localhost", "localhost", 42L, "alice", true);
        when(passkeyCredentialRepository.findVerificationByCredentialId(any(byte[].class)))
                .thenReturn(Optional.of(credential));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user));
        when(passkeyService.isClientDataOriginAllowed(any())).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"), eq("challenge-hex"), any(), any(byte[].class), any(), any()))
                .thenReturn(new PasskeyService.PasskeyVerificationResult(true, 1L));
        when(passkeyCredentialRepository.advanceSignatureCount(any(byte[].class), anyLong(), anyLong())).thenReturn(1);
        doThrow(outage).when(finalizeSignupAccount).ensureUserFinancialsReady(user, null);

        var mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(post("/auth/passkey/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"credentialId\":\"AQID\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorCode").value(errorCode))
                .andExpect(content().string(
                        not(containsString("private-"))));
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(
                any(Long.class), org.mockito.ArgumentMatchers.anyCollection(), anyLong());
        verify(redisService, never()).setValue(any(String.class), any(String.class), anyLong());
    }

    @Test
    void passkeyVerifyRequiresTotpWhenEnabled() {
        byte[] credentialId = new byte[] { 1, 2, 3 };
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");
        user.setIsActive(true);
        user.setTOTPSecret("somesecret"); // Totp enabled

        PasskeyVerificationProjection credential = new PasskeyVerificationProjection(
                credentialId, new byte[32], 0L, "ACTIVE", "localhost", "localhost", 42L, "alice", true);

        PasskeyVerifyRequest request = new PasskeyVerifyRequest();
        request.setCredentialId(Base64.getEncoder().encodeToString(credentialId));

        when(passkeyCredentialRepository.findVerificationByCredentialId(any(byte[].class)))
                .thenReturn(Optional.of(credential));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user));
        when(passkeyInventoryService.isKnownIncompatibleForCurrentLogin("localhost", "localhost")).thenReturn(false);
        when(passkeyService.isClientDataOriginAllowed(any())).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyAuthenticationAssertion(
                eq("alice"), eq("challenge-hex"), any(), any(byte[].class), any(), any()))
                .thenReturn(new PasskeyService.PasskeyVerificationResult(true, 1L));
        when(passkeyCredentialRepository.advanceSignatureCount(any(byte[].class), anyLong(), anyLong())).thenReturn(1);

        ResponseEntity<ApiResponse<Object>> response = controller.verifyAndLogin(request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertNotNull(response.getBody().getData());
        assertEquals("Passkey verified. TOTP required.", response.getBody().getMessage());
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(any(Long.class), org.mockito.ArgumentMatchers.anyCollection(), org.mockito.ArgumentMatchers.anyLong());
        verify(redisService).setValue(any(String.class), eq("alice"), eq(StartLogin.PRE_AUTH_TTL_SECONDS));
    }

    @Test
    void onboardingFinishRejectsInvalidOriginBeforeConsumingChallenge() {
        SignupState state = signupState("alice");
        when(signupStateStore.findSignupState("session-1")).thenReturn(state);
        when(passkeyService.isClientDataOriginAllowed("client-data")).thenReturn(false);
        when(passkeyService.extractOriginFromClientData("client-data"))
                .thenReturn("android:apk-key-hash:kerosene");

        ResponseEntity<ApiResponse<?>> response = controller.finishOnboardingRegistration(
                "session-1",
                registrationRequest("client-data"));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ErrorCodes.AUTH_PASSKEY_INVALID_ORIGIN, response.getBody().getErrorCode());
        verify(passkeyService, never()).consumeChallengeFromRedis("alice");
        verify(passkeyService, never()).getChallengeFromRedis("alice");
        verify(finalizeSignupAccount, never()).execute(any());
    }

    @Test
    void onboardingFinishAcceptsConfiguredAndroidOriginAndFinalizesSignup() {
        SignupState state = signupState("alice");
        UserDataBase user = new UserDataBase();
        setUserId(user, 42L);
        user.setUsername("alice");

        when(signupStateStore.findSignupState("session-1")).thenReturn(state);
        when(passkeyService.isClientDataOriginAllowed("android-client-data")).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyRegistrationSignature(
                eq("alice"),
                eq("challenge-hex"),
                eq("signature"),
                any(byte[].class),
                eq("auth-data"),
                eq("android-client-data"))).thenReturn(true);
        when(passkeyService.resolveRelyingPartyIdFromClientData("android-client-data"))
                .thenReturn("examplehiddenservice.onion");
        when(passkeyService.extractOriginHostFromClientData("android-client-data"))
                .thenReturn("android:apk-key-hash:kerosene");
        when(finalizeSignupAccount.execute("session-1")).thenReturn(user);
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, java.util.List.of("USER"), 0L)).thenReturn("jwt-token");

        ResponseEntity<ApiResponse<?>> response = controller.finishOnboardingRegistration(
                "session-1",
                registrationRequest("android-client-data"));

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("42 jwt-token", response.getBody().getData());
        verify(passkeyService).consumeChallengeFromRedis("alice");
        verify(passkeyService, never()).deleteChallengeFromRedis("alice");
        verify(finalizeSignupAccount).execute("session-1");
    }

    @Test
    void onboardingFinishConsumesChallengeWhenFinalizationDependencyIsUnavailable() {
        SignupState state = signupState("alice");

        when(signupStateStore.findSignupState("session-1")).thenReturn(state);
        when(passkeyService.isClientDataOriginAllowed("android-client-data")).thenReturn(true);
        when(passkeyService.consumeChallengeFromRedis("alice")).thenReturn("challenge-hex");
        when(passkeyService.verifyRegistrationSignature(
                eq("alice"),
                eq("challenge-hex"),
                eq("signature"),
                any(byte[].class),
                eq("auth-data"),
                eq("android-client-data"))).thenReturn(true);
        when(passkeyService.resolveRelyingPartyIdFromClientData("android-client-data"))
                .thenReturn("examplehiddenservice.onion");
        when(passkeyService.extractOriginHostFromClientData("android-client-data"))
                .thenReturn("android:apk-key-hash:kerosene");
        when(finalizeSignupAccount.execute("session-1"))
                .thenThrow(new FinancialProviderUnavailableException("custody unavailable"));

        ResponseEntity<ApiResponse<?>> result = controller.finishOnboardingRegistration(
                "session-1",
                registrationRequest("android-client-data"));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, result.getStatusCode());
        assertNotNull(result.getBody());
        assertTrue(result.getBody().getMessage().contains("temporarily unavailable"));

        verify(passkeyService).consumeChallengeFromRedis("alice");
        verify(passkeyService, never()).deleteChallengeFromRedis("alice");
    }

    @Test
    void getRegisteredDevicesRequiresAuthenticatedUser() {
        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.getRegisteredDevices();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Must be logged in to inspect passkeys", response.getBody().getMessage());
        assertEquals(ErrorCodes.AUTH_SESSION_EXPIRED, response.getBody().getErrorCode());
        verify(getPasskeyInventoryUseCase, never()).execute(anyLong());
    }

    @Test
    void getRegisteredDevicesMapsUserMissingFromUseCase() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("42", "credentials", List.of()));
        when(getPasskeyInventoryUseCase.execute(42L))
                .thenReturn(new GetPasskeyInventoryUseCase.Result(
                        GetPasskeyInventoryUseCase.Status.USER_NOT_FOUND,
                        "User not found",
                        null));

        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.getRegisteredDevices();

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("User not found", response.getBody().getMessage());
        assertEquals(ErrorCodes.AUTH_USER_NOT_FOUND, response.getBody().getErrorCode());
    }

    @Test
    void getRegisteredDevicesMapsSuccessInventory() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("42", "credentials", List.of()));
        PasskeyInventoryDTO inventory = new PasskeyInventoryDTO(true, true, false, "localhost", "localhost", List.of());
        when(getPasskeyInventoryUseCase.execute(42L))
                .thenReturn(new GetPasskeyInventoryUseCase.Result(
                        GetPasskeyInventoryUseCase.Status.FOUND,
                        null,
                        inventory));

        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.getRegisteredDevices();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Registered passkeys retrieved successfully.", response.getBody().getMessage());
        assertEquals(inventory, response.getBody().getData());
    }

    @Test
    void blockDeviceRequiresAuthenticatedUser() {
        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.blockDevice("device-1");

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Must be logged in to update devices", response.getBody().getMessage());
        assertEquals(ErrorCodes.AUTH_SESSION_EXPIRED, response.getBody().getErrorCode());
        verify(updatePasskeyDeviceStatusUseCase, never()).execute(anyLong(), any(), any());
    }

    @Test
    void blockDeviceMapsUserMissingFromUseCase() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("42", "credentials", List.of()));
        when(updatePasskeyDeviceStatusUseCase.execute(42L, "device-1", "BLOCKED"))
                .thenReturn(new UpdatePasskeyDeviceStatusUseCase.Result(
                        UpdatePasskeyDeviceStatusUseCase.Status.USER_NOT_FOUND,
                        "User not found",
                        null));

        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.blockDevice("device-1");

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("User not found", response.getBody().getMessage());
        assertEquals(ErrorCodes.AUTH_USER_NOT_FOUND, response.getBody().getErrorCode());
    }

    @Test
    void revokeDeviceMapsDeviceMissingFromUseCase() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("42", "credentials", List.of()));
        when(updatePasskeyDeviceStatusUseCase.execute(42L, "device-1", "REVOKED"))
                .thenReturn(new UpdatePasskeyDeviceStatusUseCase.Result(
                        UpdatePasskeyDeviceStatusUseCase.Status.DEVICE_NOT_FOUND,
                        "Device not found",
                        null));

        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.revokeDevice("device-1");

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Device not found", response.getBody().getMessage());
        assertEquals(ErrorCodes.AUTH_PASSKEY_CREDENTIAL_NOT_FOUND, response.getBody().getErrorCode());
    }

    @Test
    void revokeDeviceMapsSuccessMessageAndInventory() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("42", "credentials", List.of()));
        PasskeyInventoryDTO inventory = new PasskeyInventoryDTO(true, true, false, "localhost", "localhost", List.of());
        when(updatePasskeyDeviceStatusUseCase.execute(42L, "device-1", "REVOKED"))
                .thenReturn(new UpdatePasskeyDeviceStatusUseCase.Result(
                        UpdatePasskeyDeviceStatusUseCase.Status.UPDATED,
                        null,
                        inventory));

        ResponseEntity<ApiResponse<PasskeyInventoryDTO>> response = controller.revokeDevice("device-1");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Authenticated device revoked.", response.getBody().getMessage());
        assertEquals(inventory, response.getBody().getData());
    }

    private SignupState signupState(String username) {
        SignupState state = new SignupState();
        state.setUsername(username);
        return state;
    }

    private UserDataBase activeUser(String username, Long id) {
        UserDataBase user = new UserDataBase();
        setUserId(user, id);
        user.setUsername(username);
        user.setIsActive(true);
        return user;
    }

    private PasskeyVerificationProjection activeCredential(byte[] credentialId, long signatureCount) {
        return new PasskeyVerificationProjection(
                credentialId,
                new byte[32],
                signatureCount,
                "ACTIVE",
                "kerosene-device",
                "localhost",
                42L,
                "alice",
                true);
    }

    private PasskeyVerifyRequest verifyRequest(String username, byte[] credentialId) {
        PasskeyVerifyRequest request = new PasskeyVerifyRequest();
        request.setUsername(username);
        request.setCredentialId(Base64.getEncoder().encodeToString(credentialId));
        request.setSignature("raw-signature-secret");
        request.setAuthData("raw-authdata-secret");
        request.setClientDataJSON("raw-clientdata-secret");
        return request;
    }

    private PasskeyRegistrationRequest registrationRequest(String clientDataJson) {
        PasskeyRegistrationRequest request = new PasskeyRegistrationRequest();
        request.setClientDataJSON(clientDataJson);
        request.setPublicKeyCose(Base64.getEncoder().encodeToString(new byte[32]));
        request.setSignature("signature");
        request.setAuthData("auth-data");
        request.setCredentialId("credential-id");
        request.setUserHandle("user-handle");
        request.setDeviceName("Android");
        return request;
    }

    private void setUserId(UserDataBase user, Long id) {
        try {
            java.lang.reflect.Field field = UserDataBase.class.getDeclaredField("id");
            field.setAccessible(true);
            field.set(user, id);
        } catch (ReflectiveOperationException exception) {
            throw new RuntimeException(exception);
        }
    }

    private ListAppender<ILoggingEvent> attachPasskeyOrchestratorLogAppender() {
        Logger logger = (Logger) LoggerFactory.getLogger(PasskeyOrchestrator.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        return appender;
    }

    private void detachPasskeyOrchestratorLogAppender(ListAppender<ILoggingEvent> appender) {
        Logger logger = (Logger) LoggerFactory.getLogger(PasskeyOrchestrator.class);
        logger.detachAppender(appender);
    }

    private String formattedMessages(ListAppender<ILoggingEvent> appender) {
        return appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce("", (left, right) -> left + "\n" + right);
    }

    private boolean hasAuthMarker(ListAppender<ILoggingEvent> appender) {
        return appender.list.stream()
                .anyMatch(event -> event.getMarkerList() != null
                        && event.getMarkerList().stream().anyMatch(marker -> "AUTH".equals(marker.getName())));
    }

    private void assertSafePasskeyFailureLog(String logs, PasskeyVerifyRequest request, byte[] credentialId) {
        assertTrue(logs.contains("usernamePresent=true"));
        assertTrue(logs.contains("credentialIdPresent=true"));
        assertTrue(logs.contains("credentialRef=sha256:"));

        assertFalse(logs.contains("alice"));
        assertFalse(logs.contains(request.getCredentialId()));
        assertFalse(logs.contains(new String(credentialId, StandardCharsets.UTF_8)));
        assertFalse(logs.contains(request.getSignature()));
        assertFalse(logs.contains(request.getAuthData()));
        assertFalse(logs.contains(request.getClientDataJSON()));
    }
}
