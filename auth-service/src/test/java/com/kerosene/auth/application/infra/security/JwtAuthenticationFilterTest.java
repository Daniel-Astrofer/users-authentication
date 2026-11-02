package com.kerosene.auth.application.infra.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import io.jsonwebtoken.Jwts;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;
import com.kerosene.auth.AuthConstants;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.validation.jwt.JwtService;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        var users = mock(com.kerosene.auth.application.port.out.AuthUserGateway.class);
        when(users.findCredentialEpochById(org.mockito.ArgumentMatchers.anyLong())).thenReturn(java.util.Optional.of(0L));
        ReflectionTestUtils.setField(jwtService, "userGateway", users);
        ReflectionTestUtils.setField(jwtService, "secretKey", "01234567890123456789012345678901");
        filter = new JwtAuthenticationFilter(jwtService, mock(HandlerExceptionResolver.class));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldPopulateUserAuthorityForRegularToken() throws Exception {
        String token = jwtService.generateToken(1L, List.of("USER"));
        MockHttpServletRequest request = request(token);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .anyMatch(authority -> "ROLE_USER".equals(authority.getAuthority())));
        assertFalse(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority())));
    }

    @Test
    void shouldPopulateAdminAuthorityOnlyWhenTokenCarriesAdminRole() throws Exception {
        String token = jwtService.generateToken(2L, List.of("ADMIN"));
        MockHttpServletRequest request = request(token);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority())));
    }

    @Test
    void shouldPreserveRolesWhenRenewingToken() throws Exception {
        String token = jwtService.generateToken(3L, List.of("ADMIN"));
        String originalSessionId = jwtService.extractSessionId(token);
        JwtService renewingJwtService = spy(jwtService);
        doReturn(true).when(renewingJwtService).shouldRenewToken(token);
        JwtAuthenticationFilter renewingFilter = new JwtAuthenticationFilter(
                renewingJwtService,
                mock(HandlerExceptionResolver.class));
        MockHttpServletResponse response = new MockHttpServletResponse();

        renewingFilter.doFilter(request(token), response, new MockFilterChain());

        String renewedToken = response.getHeader("X-New-Token");
        assertTrue(renewingJwtService.extractRoles(renewedToken).contains("ADMIN"));
        assertEquals(originalSessionId, renewingJwtService.extractSessionId(renewedToken));
    }

    @Test
    void shouldNotExposeRawTokenErrorInInvalidSessionResponse() throws Exception {
        HandlerExceptionResolver resolver = mock(HandlerExceptionResolver.class);
        JwtAuthenticationFilter resolvingFilter = new JwtAuthenticationFilter(jwtService, resolver);

        resolvingFilter.doFilter(request("not-a-token"), new MockHttpServletResponse(), new MockFilterChain());

        org.mockito.ArgumentCaptor<AuthExceptions.InvalidCredentials> captor =
                org.mockito.ArgumentCaptor.forClass(AuthExceptions.InvalidCredentials.class);
        verify(resolver).resolveException(any(), any(), isNull(), captor.capture());
        assertEquals("invalid session", captor.getValue().getMessage());
    }

    @Test
    void shouldRejectRevokedJwtSession() throws Exception {
        RedisServicer redisService = mock(RedisServicer.class);
        ReflectionTestUtils.setField(jwtService, "redisService", redisService);
        String token = jwtService.generateToken(4L, List.of("USER"));
        when(redisService.isJwtSessionRevoked(jwtService.extractSessionId(token))).thenReturn(true);
        HandlerExceptionResolver resolver = mock(HandlerExceptionResolver.class);
        JwtAuthenticationFilter resolvingFilter = new JwtAuthenticationFilter(jwtService, resolver);

        resolvingFilter.doFilter(request(token), new MockHttpServletResponse(), new MockFilterChain());

        org.mockito.ArgumentCaptor<AuthExceptions.InvalidCredentials> captor =
                org.mockito.ArgumentCaptor.forClass(AuthExceptions.InvalidCredentials.class);
        verify(resolver).resolveException(any(), any(), isNull(), captor.capture());
        assertEquals("invalid session", captor.getValue().getMessage());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void shouldAcceptLegacyJwtWithoutSessionId() throws Exception {
        String legacyToken = Jwts.builder()
                .subject("5")
                .id("5")
                .claim("roles", List.of("USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + AuthConstants.JWT_EXPIRATION_TIME))
                .signWith(jwtService.getSecretKey())
                .compact();

        filter.doFilter(request(legacyToken), new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(5L, SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    private MockHttpServletRequest request(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/trigger");
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }
}
