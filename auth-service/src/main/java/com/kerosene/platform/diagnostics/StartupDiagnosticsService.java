package com.kerosene.platform.diagnostics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

/**
 * Performs fast in-process startup diagnostics from Spring configuration only.
 * The checks intentionally avoid sockets, providers, repositories, and bean availability calls
 * so failure logs remain available even when infrastructure dependencies are down.
 */
@Service
public class StartupDiagnosticsService {

    private static final List<String> REQUIRED_DATASOURCE_PROPERTIES = List.of(
            "spring.datasource.url",
            "spring.datasource.username",
            "spring.datasource.password");
    private static final List<String> REQUIRED_REDIS_PROPERTIES = List.of(
            "spring.data.redis.host",
            "spring.data.redis.port");
    private static final List<String> REQUIRED_INTERNAL_SERVICE_PROPERTIES = List.of(
            "kfe.internal.base-url",
            "kfe.remote.base-url");
    private static final List<String> REQUIRED_LND_PROPERTIES = List.of(
            "lightning.lnd.enabled",
            "lightning.lnd.host",
            "lightning.lnd.port",
            "lightning.lnd.tls.enabled");
    private static final List<String> REQUIRED_KFE_PROPERTIES = List.of(
            "kfe.receive.bitcoin-core-wallet-address-enabled",
            "kfe.network-monitor.enabled",
            "transactions.local-derived-address-fallback-enabled",
            "transactions.bitcoin-core-wallet-address-enabled");
    private static final List<String> PROD_REQUIRED_PROPERTIES = List.of(
            "app.cors.allowed-origins",
            "webauthn.relying-party-id",
            "webauthn.origins",
            "shard.attestation.secret",
            "kfe.internal.base-url",
            "kfe.remote.base-url",
            "kerosene.workload-identity.socket",
            "kerosene.workload-identity.own-spiffe-id",
            "kerosene.workload-identity.peer-spiffe-id");
    private static final List<String> PROD_TRUE_PROPERTIES = List.of(
            "kfe.vaultmesh.enabled",
            "kerosene.workload-identity.enabled",
            "bitcoin.rpc.enabled",
            "bitcoin.rpc.required",
            "bitcoin.rpc.pruned-required",
            "tor.health.required",
            "release.attestation.required",
            "release.attestation.remote.enabled");
    private static final List<String> PROD_FALSE_PROPERTIES = List.of(
            "lightning.lnd.enabled",
            "bitcoin.mock-mode",
            "custody.mock-mode",
            "quorum.allow-local-simulation",
            "treasury.siphon.manual-settlement-enabled",
            "transactions.onchain.test-instant-settlement-enabled",
            "transactions.local-derived-address-fallback-enabled",
            "voucher.mock.accept-any-txid");

    private final Environment environment;

    public StartupDiagnosticsService(Environment environment) {
        this.environment = environment;
    }

    /**
     * Builds a diagnostic report for startup readiness and failure logs. Missing or unsafe critical
     * production configuration is reported as FAIL, while local operational gaps remain WARN.
     */
    public StartupDiagnosticReport diagnose() {
        List<StartupDiagnosticCheck> checks = new ArrayList<>();
        checks.add(checkProfiles());
        checks.add(requiredProperties("datasource", REQUIRED_DATASOURCE_PROPERTIES));
        checks.add(requiredProperties("redis", REQUIRED_REDIS_PROPERTIES));
        checks.add(requiredProperties("kfeTransport", REQUIRED_INTERNAL_SERVICE_PROPERTIES));
        checks.add(environment.getProperty("lightning.lnd.enabled", Boolean.class, false)
                ? requiredProperties("lnd", REQUIRED_LND_PROPERTIES)
                : ok("lnd", "Lightning disabled by custody policy", List.of("lightning.lnd.enabled")));
        checks.add(requiredProperties("kfe", REQUIRED_KFE_PROPERTIES));
        checks.add(checkFlywayBaselineSafety());
        checks.add(checkProductionSafety());
        checks.add(checkKfeOnlyAssumptions());
        return new StartupDiagnosticReport(checks);
    }

    private StartupDiagnosticCheck checkProfiles() {
        List<String> profiles = Arrays.asList(environment.getActiveProfiles());
        if (profiles.isEmpty()) {
            return warn("profiles", "no active Spring profile", List.of("default profile only"));
        }
        return ok("profiles", "active profiles configured", profiles);
    }

    private StartupDiagnosticCheck requiredProperties(String name, List<String> properties) {
        List<String> missing = properties.stream().filter(this::isBlank).toList();
        if (missing.isEmpty()) {
            return ok(name, "required properties present", sanitizePropertyNames(properties));
        }
        return fail(name, "required properties missing", sanitizePropertyNames(missing));
    }

    private StartupDiagnosticCheck checkFlywayBaselineSafety() {
        boolean baselineOnMigrate = environment.getProperty("spring.flyway.baseline-on-migrate", Boolean.class, false);
        boolean flywayEnabled = environment.getProperty("spring.flyway.enabled", Boolean.class, false);
        boolean prod = isProductionProfile();
        if (prod && baselineOnMigrate) {
            return fail("flyway", "baseline-on-migrate is unsafe in production", List.of("spring.flyway.baseline-on-migrate"));
        }
        if (!flywayEnabled) {
            return warn("flyway", "Flyway is disabled", List.of("spring.flyway.enabled"));
        }
        return ok("flyway", "Flyway baseline settings are safe", List.of("spring.flyway.enabled", "spring.flyway.baseline-on-migrate"));
    }

    private StartupDiagnosticCheck checkProductionSafety() {
        if (!isProductionProfile()) {
            return ok("prod-safety", "production profile not active", List.of());
        }

        List<String> violations = new ArrayList<>();
        PROD_REQUIRED_PROPERTIES.stream().filter(this::isBlank).forEach(property -> violations.add(property + " missing"));
        PROD_TRUE_PROPERTIES.stream()
                .filter(property -> !environment.getProperty(property, Boolean.class, false))
                .forEach(property -> violations.add(property + " must be true"));
        PROD_FALSE_PROPERTIES.stream()
                .filter(property -> environment.getProperty(property, Boolean.class, false))
                .forEach(property -> violations.add(property + " must be false"));

        String corsOrigins = environment.getProperty("app.cors.allowed-origins", "");
        if (corsOrigins.contains("*")) {
            violations.add("app.cors.allowed-origins must not contain wildcard");
        }
        if (corsOrigins.contains("localhost") || corsOrigins.contains("127.0.0.1")) {
            violations.add("app.cors.allowed-origins must not contain localhost");
        }


        if (violations.isEmpty()) {
            return ok("prod-safety", "production safety properties pass", List.of());
        }
        return fail("prod-safety", "production safety violations found", violations);
    }

    private StartupDiagnosticCheck checkKfeOnlyAssumptions() {
        List<String> violations = new ArrayList<>();
        if (!isBlank("transactions.local-derived-address-fallback-enabled")
                && environment.getProperty("transactions.local-derived-address-fallback-enabled", Boolean.class, false)) {
            violations.add("transactions.local-derived-address-fallback-enabled must be false");
        }
        if (violations.isEmpty()) {
            return ok("kfe-only", "KFE-only runtime assumptions pass", List.of());
        }
        return fail("kfe-only", "KFE-only runtime assumptions violated", violations);
    }

    private boolean isProductionProfile() {
        String legacyProfile = environment.getProperty("activeProfile", "");
        return Arrays.stream(environment.getActiveProfiles()).anyMatch(this::isProductionName)
                || isProductionName(legacyProfile);
    }

    private boolean isProductionName(String profile) {
        return "prod".equalsIgnoreCase(profile) || "production".equalsIgnoreCase(profile);
    }

    private boolean isBlank(String property) {
        return environment.getProperty(property, "").isBlank();
    }

    private List<String> sanitizePropertyNames(List<String> propertyNames) {
        return propertyNames.stream().map(this::sanitizePropertyName).toList();
    }

    private String sanitizePropertyName(String propertyName) {
        if (propertyName.contains("password")
                || propertyName.contains("secret")
                || propertyName.contains("token")
                || propertyName.contains("macaroon")
                || propertyName.contains("private-key")
                || propertyName.contains("api-key")) {
            return propertyName + "=<redacted>";
        }
        return propertyName;
    }

    private StartupDiagnosticCheck ok(String name, String message, List<String> details) {
        return new StartupDiagnosticCheck(StartupDiagnosticStatus.OK, name, message, details);
    }

    private StartupDiagnosticCheck warn(String name, String message, List<String> details) {
        return new StartupDiagnosticCheck(StartupDiagnosticStatus.WARN, name, message, details);
    }

    private StartupDiagnosticCheck fail(String name, String message, List<String> details) {
        return new StartupDiagnosticCheck(StartupDiagnosticStatus.FAIL, name, message, details);
    }
}
