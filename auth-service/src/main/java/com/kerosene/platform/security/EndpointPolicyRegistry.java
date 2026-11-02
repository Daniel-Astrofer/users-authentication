package com.kerosene.platform.security;

import jakarta.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

/** Central path-pattern inventory assigning HTTP endpoints to public, admin, or authenticated access. */
@Component
public class EndpointPolicyRegistry {

    /** Access classes used by the security configuration and policy coverage checks. */
    public enum Policy {
        /** Endpoint can be accessed without an authenticated principal. */
        PUBLIC,
        CERTIFICATE_ONLY,
        /** Endpoint requires an administrator principal. */
        ADMIN,
        /** Endpoint requires any authenticated principal. */
        AUTHENTICATED
    }

    /** Spring-compatible matcher used to evaluate Ant-style endpoint patterns. */
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();
    public static final String BANK_RELEASE_OBSERVATION = "/v1/releases/observation";
    private static final String[] CERTIFICATE_ONLY = {BANK_RELEASE_OBSERVATION, BANK_RELEASE_OBSERVATION + "/**"};

    /** Endpoint patterns requiring an authenticated principal, including ordinary user APIs. */
    private static final String[] AUTHENTICATED = {
            "/auth/activation-status",
            "/auth/activation-status/**",
            "/auth/backup-codes",
            "/auth/backup-codes/**",
            "/auth/device-key/**",
            "/auth/logout",
            "/auth/me",
            "/auth/passkey/**",
            "/auth/security-status",
            "/auth/security/**",
            "/auth/totp",
            "/auth/totp/**",
            "/api/economy/**",
            "/audit/**",
            "/health/dependencies",
            "/notifications",
            "/notifications/**",
            "/content",
            "/content/**",
            "/quorum/**",
            "/sovereignty/reattest",
            "/sovereignty/telemetry",
            "/users/*/receiving-capabilities"
    };

    /** Endpoint patterns restricted to administrator principals and admin infrastructure. */
    private static final String[] ADMIN = {
            "/api/admin/**",
            "/auth/admin/access-attempts/**",
            "/auth/admin/devices",
            "/auth/admin/devices/**",
            "/auth/admin/key",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/configuration/security",
            "/configuration/ui",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/webjars/**"
    };

    /** Explicitly public routes, including login/onboarding, health, and static client assets. */
    private static final String[] PUBLIC = {
            "/",
            "/bitcoin-banking",
            "/bitcoin-banking/**",
            "/admin",
            "/admin/**",
            "/download",
            "/status",
            "/index.html",
            "/favicon.png",
            "/manifest.json",
            "/version.json",
            "/flutter.js",
            "/flutter_bootstrap.js",
            "/flutter_service_worker.js",
            "/main.dart.js",
            "/assets/**",
            "/canvaskit/**",
            "/icons/**",
            "/healthz",
            "/health/live",
            "/health/ready",
            "/api/public/**",
            "/internal/kfe/**",
            "/internal/content/**",
            "/system/release",
            "/auth/signup",
            "/auth/signup/totp/verify",
            "/auth/login",
            "/auth/login/totp/verify",
            "/auth/admin/login",
            "/auth/admin/login/*",
            "/auth/passkey/challenge",
            "/auth/passkey/verify",
            "/auth/passkey/onboarding/start",
            "/auth/passkey/onboarding/finish",
            "/auth/device-key/challenge",
            "/auth/device-key/onboarding/start",
            "/auth/device-key/onboarding/finish",
            "/auth/device-key/verify",
            "/auth/recovery/emergency/start",
            "/auth/recovery/emergency/finish",
            "/auth/recovery/emergency/device-key/challenge",
            "/auth/pow/challenge",
            "/integrations/btcpay/webhook/**",
            "/actuator/health",
            "/actuator/health/**",
            "/sovereignty/ping",
            "/sovereignty/status",
            "/kfe/**",
            "/error",
            "/ws/**"
    };

    /** Creates the registry over the statically declared policy pattern sets. */
    public EndpointPolicyRegistry() {
    }

    /** Validates that policy sets are nonempty, patterns are rooted, and exact patterns are unique.
     * @throws IllegalStateException when the registry contains a structural policy error
     */
    @PostConstruct
    public void validate() {
        Map<String, Policy> seen = new LinkedHashMap<>();
        List<String> errors = new ArrayList<>();

        registerForValidation(seen, errors, Policy.CERTIFICATE_ONLY, CERTIFICATE_ONLY);
        registerForValidation(seen, errors, Policy.PUBLIC, PUBLIC);
        registerForValidation(seen, errors, Policy.ADMIN, ADMIN);
        registerForValidation(seen, errors, Policy.AUTHENTICATED, AUTHENTICATED);

        if (!errors.isEmpty()) {
            throw new IllegalStateException("Invalid endpoint policy registry: " + String.join("; ", errors));
        }
    }

    /** Returns a defensive copy of all authenticated endpoint patterns.
     * @return copied authenticated pattern array
     */
    public String[] authenticatedEndpoints() {
        return AUTHENTICATED.clone();
    }

    /** Returns a defensive copy of all administrator endpoint patterns.
     * @return copied administrator pattern array
     */
    public String[] adminEndpoints() {
        return ADMIN.clone();
    }

    /** Returns a defensive copy of all public endpoint patterns.
     * @return copied public pattern array
     */
    public String[] publicEndpoints() {
        return PUBLIC.clone();
    }

    /** Resolves the declared policy for a path using public, admin, then authenticated precedence.
     * @param path request path, with or without a leading slash
     * @return matching policy, or empty when no pattern declares the path
     */
    public Optional<Policy> policyFor(String path) {
        String normalizedPath = normalize(path);
        for (String pattern : CERTIFICATE_ONLY) {
            if (PATH_MATCHER.match(pattern, normalizedPath)) return Optional.of(Policy.CERTIFICATE_ONLY);
        }
        for (String pattern : PUBLIC) {
            if (PATH_MATCHER.match(pattern, normalizedPath)) {
                return Optional.of(Policy.PUBLIC);
            }
        }
        for (String pattern : ADMIN) {
            if (PATH_MATCHER.match(pattern, normalizedPath)) {
                return Optional.of(Policy.ADMIN);
            }
        }
        for (String pattern : AUTHENTICATED) {
            if (PATH_MATCHER.match(pattern, normalizedPath)) {
                return Optional.of(Policy.AUTHENTICATED);
            }
        }
        return Optional.empty();
    }

    /** Reports whether any policy pattern explicitly covers the given path.
     * @param path request path to check
     * @return true when {@link #policyFor(String)} resolves a policy
     */
    public boolean hasDeclaredPolicy(String path) {
        return policyFor(path).isPresent();
    }

    /** Adds every pattern in one policy group to the shared structural validation pass.
     * @param seen patterns already assigned to a policy
     * @param errors validation errors accumulated for startup failure
     * @param policy policy owning this pattern group
     * @param patterns endpoint patterns to validate
     */
    private void registerForValidation(
            Map<String, Policy> seen,
            List<String> errors,
            Policy policy,
            String[] patterns) {
        if (patterns.length == 0) {
            errors.add(policy + " policy has no endpoint patterns");
        }
        Arrays.stream(patterns).forEach(pattern -> validatePattern(seen, errors, policy, pattern));
    }

    /** Checks one pattern's basic syntax and detects exact duplicates across policy groups.
     * @param seen patterns already assigned to a policy
     * @param errors validation errors accumulated for startup failure
     * @param policy policy that declares the pattern
     * @param pattern endpoint path pattern to inspect
     */
    private void validatePattern(Map<String, Policy> seen, List<String> errors, Policy policy, String pattern) {
        if (pattern == null || pattern.isBlank()) {
            errors.add(policy + " policy contains a blank pattern");
            return;
        }
        if (!pattern.startsWith("/")) {
            errors.add(policy + " pattern must start with '/': " + pattern);
        }
        Policy previousPolicy = seen.putIfAbsent(pattern, policy);
        if (previousPolicy != null) {
            errors.add("duplicate pattern " + pattern + " in " + previousPolicy + " and " + policy);
        }
    }

    /** Converts null/blank paths to root and adds the leading slash expected by route patterns.
     * @param path request path provided by the caller
     * @return normalized absolute path
     */
    private String normalize(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }
}
