package com.kerosene.auth.application.infra.security;

import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.HandlerExceptionResolver;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.application.service.validation.jwt.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // Paths where the HTTP filter should NOT abort on JWT failure.
    // WebSocket upgrade requests are authenticated at the STOMP layer instead.
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();
    private static final java.util.List<String> SKIP_BLOCK_PATHS = java.util.List.of("/ws/**");

    private final JwtServicer jwtService;
    private final JwtService jwtServiceImpl;
    private final HandlerExceptionResolver resolver;

    public JwtAuthenticationFilter(
            @Qualifier("JwtService") JwtServicer jwtService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.jwtService = jwtService;
        this.jwtServiceImpl = (JwtService) jwtService;
        this.resolver = resolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String bank = com.kerosene.platform.security.EndpointPolicyRegistry.BANK_RELEASE_OBSERVATION;
        return path.equals(bank) || path.startsWith(bank + "/");
    }

    private boolean isSkipBlockPath(String path) {
        return SKIP_BLOCK_PATHS.stream().anyMatch(p -> PATH_MATCHER.match(p, path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        String token = null;

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
        }
        // ⚠️ JWT via query parameter (?token=...) was intentionally removed.
        // Tokens in URLs appear in proxy logs, access logs, browser history, and
        // HTTP Referer headers — all of which are high-risk forensic surfaces.
        // Authentication MUST use the Authorization: Bearer header only.

        if (token != null) {
            UsernamePasswordAuthenticationToken auth = null;
            try {
                if (jwtService.isSessionRevoked(token)) {
                    throw new AuthExceptions.InvalidCredentials("invalid session");
                }
                Long userId = jwtService.extractId(token);

                List<SimpleGrantedAuthority> authorities = jwtService.extractRoles(token).stream()
                        .map(this::toAuthority)
                        .distinct()
                        .toList();
                auth = new UsernamePasswordAuthenticationToken(userId, token, authorities);

                // Check if the token needs renewal
                if (jwtServiceImpl.shouldRenewToken(token)) {
                    String newToken = jwtServiceImpl.renewToken(token);
                    response.setHeader("X-New-Token", newToken);
                }

            } catch (Exception e) {
                log.warn("JWT Authentication Error for path {}", request.getServletPath());
                // For WebSocket upgrade paths (/ws/**), do NOT abort the request.
                // The STOMP-level interceptor in WebSocketConfig handles authentication
                // AFTER the HTTP upgrade. Returning 401 here prevents the upgrade entirely.
                if (isSkipBlockPath(request.getServletPath())) {
                    log.debug("Skipping JWT block for WS path: {}", request.getServletPath());
                } else {
                    resolver.resolveException(request, response, null,
                            new AuthExceptions.InvalidCredentials("invalid session"));
                    return;
                }
            }
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }

    private SimpleGrantedAuthority toAuthority(String role) {
        String normalized = role == null ? "USER" : role.trim().toUpperCase();
        if (!normalized.startsWith("ROLE_")) {
            normalized = "ROLE_" + normalized;
        }
        return new SimpleGrantedAuthority(normalized);
    }

}
