package com.kerosene.auth.application.service.validation.jwt;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.platform.config.websocket.StompSessionAuthorization;
import com.kerosene.platform.config.websocket.StompOutboundChannelInterceptor;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class CredentialEpochSessionTest {
    private JwtService jwt;
    private AuthUserGateway users;
    private final AtomicLong epoch = new AtomicLong();
    @BeforeEach
    void setup() {
        jwt = new JwtService(); users = mock(AuthUserGateway.class);
        ReflectionTestUtils.setField(jwt,"secretKey","01234567890123456789012345678901");
        ReflectionTestUtils.setField(jwt,"userGateway",users);
        when(users.findCredentialEpochById(42L)).thenAnswer(i->Optional.of(epoch.get()));
    }

    @Test
    void recoveryInvalidatesEveryOlderSessionAndAllowsANewVerifiedGeneration() {
        String first = jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L);
        String second = jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L);
        assertThat(jwt.isSessionRevoked(first)).isFalse();assertThat(jwt.isSessionRevoked(second)).isFalse();
        epoch.incrementAndGet();
        assertThat(jwt.isSessionRevoked(first)).isTrue();assertThat(jwt.isSessionRevoked(second)).isTrue();
        String fresh = jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),1L);
        assertThat(jwt.isSessionRevoked(fresh)).isFalse();
    }

    @Test
    void legacyTokensAreGenerationZeroAndCannotSurviveRecovery() {
        String legacy = Jwts.builder().id("42").subject("42").issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+60000)).signWith(jwt.getSecretKey()).compact();
        assertThat(jwt.isSessionRevoked(legacy)).isFalse();epoch.incrementAndGet();
        assertThat(jwt.isSessionRevoked(legacy)).isTrue();
    }

    @Test
    void aProofVerifiedBeforeRecoveryCannotMintANewGenerationToken() {
        epoch.incrementAndGet();
        assertThatThrownBy(()->jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L))
                .isInstanceOf(AuthExceptions.InvalidCredentials.class);
    }

    @Test
    void renewalPreservesTheVerifiedGenerationAndCannotResurrectARevokedSession() {
        String token = jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L);
        String renewed = jwt.renewToken(token);
        assertThat(jwt.extractSessionId(renewed)).isEqualTo(jwt.extractSessionId(token));
        epoch.incrementAndGet();
        assertThat(jwt.isSessionRevoked(renewed)).isTrue();
        assertThatThrownBy(()->jwt.renewToken(token)).isInstanceOf(AuthExceptions.InvalidCredentials.class);
    }

    @Test
    void privateBrokerFramesAreDeniedAfterRecoveryEvenWithoutAStompAccessor() {
        var sessions = new StompSessionAuthorization(jwt);
        sessions.register("fixture-socket",jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L));
        var interceptor = new StompOutboundChannelInterceptor(sessions);
        var headers = SimpMessageHeaderAccessor.create(SimpMessageType.MESSAGE);
        headers.setSessionId("fixture-socket");
        var message = MessageBuilder.createMessage("PUBLIC_FIXTURE_EVENT",headers.getMessageHeaders());
        assertThat(interceptor.preSend(message,null)).isSameAs(message);
        epoch.incrementAndGet();
        assertThat(interceptor.preSend(message,null)).isNull();
        sessions.remove("fixture-socket");assertThat(sessions.isAuthorized("fixture-socket")).isFalse();
    }

    @Test
    void anUnavailableAccountEpochNeverAuthorizesDelivery() {
        String token = jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L);
        var sessions = new StompSessionAuthorization(jwt);sessions.register("fixture-socket",token);
        when(users.findCredentialEpochById(42L)).thenThrow(new IllegalStateException("PUBLIC_FIXTURE_FAILURE"));
        assertThat(sessions.isAuthorized("fixture-socket")).isFalse();
        assertThatThrownBy(()->jwt.isSessionRevoked(token)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aSecondConnectCannotReplaceTheExistingSocketOwner() {
        var sessions = new StompSessionAuthorization(jwt);
        sessions.register("fixture-socket",jwt.generateTokenAtCredentialEpoch(42L,List.of("USER"),0L));
        assertThatThrownBy(()->sessions.register("fixture-socket","FOREIGN_FIXTURE_TOKEN"))
                .isInstanceOf(org.springframework.messaging.MessageDeliveryException.class);
        assertThat(sessions.isAuthorized("fixture-socket")).isTrue();
    }
}
