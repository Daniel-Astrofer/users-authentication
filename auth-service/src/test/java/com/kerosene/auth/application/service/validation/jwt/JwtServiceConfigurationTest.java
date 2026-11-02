package com.kerosene.auth.application.service.validation.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceConfigurationTest {
    private final ApplicationContextRunner context = new ApplicationContextRunner().withBean(JwtService.class)
            .withBean(com.kerosene.auth.application.port.out.AuthUserGateway.class, () -> {
                var users = org.mockito.Mockito.mock(com.kerosene.auth.application.port.out.AuthUserGateway.class);
                org.mockito.Mockito.when(users.findCredentialEpochById(org.mockito.ArgumentMatchers.anyLong()))
                        .thenReturn(java.util.Optional.of(0L));
                return users;
            });

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "test-key-too-short", "1234567890123456789012345678901"})
    void rejectsShortKeyAtStartupBeforeAcceptingSignup(String key) {
        context.withPropertyValues("api.secret.token.secret=" + key).run(application -> {
            assertThat(application).hasFailed();
            assertThat(application.getStartupFailure()).hasRootCauseInstanceOf(IllegalStateException.class)
                    .hasRootCauseMessage("JWT signing key must contain at least 32 UTF-8 bytes");
        });
    }

    @Test
    void validSharedKeyCanIssueAndVerifyToken() {
        context.withPropertyValues("api.secret.token.secret=01234567890123456789012345678901")
                .run(application -> {
                    assertThat(application).hasNotFailed();
                    JwtService service = application.getBean(JwtService.class);
                    String token = service.generateToken(42);
                    assertThat(service.extractId(token)).isEqualTo(42);
                    var claims = io.jsonwebtoken.Jwts.parser().verifyWith(service.getSecretKey())
                            .build().parseSignedClaims(token).getPayload();
                    assertThat(claims.getIssuer()).isEqualTo("Kerosene-Auth");
                    assertThat(claims.getAudience()).containsExactly("kerosene-app");
                    assertThat(service.extractRoles(token)).containsExactly("USER");
                    assertThat(service.extractSessionId(token)).isNotBlank();
                });
    }
}
