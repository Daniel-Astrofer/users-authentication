package com.kerosene.platform.diagnostics;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class StartupDiagnosticsServiceTest {

    @Test
    void reportsOkForCompleteNonProductionConfiguration() {
        StartupDiagnosticReport report = new StartupDiagnosticsService(baseEnvironment()).diagnose();

        assertThat(report.status()).isEqualTo(StartupDiagnosticStatus.OK);
        assertThat(report.failCount()).isZero();
    }

    @Test
    void reportsProductionSafetyFailuresWithoutSecretValues() {
        MockEnvironment environment = baseEnvironment()
                .withProperty("spring.flyway.baseline-on-migrate", "true")
                .withProperty("app.cors.allowed-origins", "http://localhost:3000")
                .withProperty("spring.datasource.password", "super-secret-password");
        environment.setActiveProfiles("prod");

        StartupDiagnosticReport report = new StartupDiagnosticsService(environment).diagnose();

        assertThat(report.status()).isEqualTo(StartupDiagnosticStatus.FAIL);
        assertThat(report.toLogSummary())
                .contains("flyway:FAIL")
                .contains("prod-safety:FAIL")
                .contains("spring.datasource.password=<redacted>")
                .doesNotContain("super-secret-password");
    }

    @Test
    void reportsKfeOnlyViolations() {
        MockEnvironment environment = baseEnvironment()
                .withProperty("transactions.local-derived-address-fallback-enabled", "true");

        StartupDiagnosticReport report = new StartupDiagnosticsService(environment).diagnose();

        assertThat(report.status()).isEqualTo(StartupDiagnosticStatus.FAIL);
        assertThat(report.toLogSummary())
                .contains("kfe-only:FAIL")
                .contains("transactions.local-derived-address-fallback-enabled must be false");
    }

    @Test
    void warnsWhenFlywayIsDisabled() {
        MockEnvironment environment = baseEnvironment().withProperty("spring.flyway.enabled", "false");

        StartupDiagnosticReport report = new StartupDiagnosticsService(environment).diagnose();

        assertThat(report.status()).isEqualTo(StartupDiagnosticStatus.WARN);
        assertThat(report.toLogSummary()).contains("flyway:WARN");
    }

    @Test
    void productionDiagnosticsFollowAuthOwnershipAndDisabledLightning() {
        var environment = baseEnvironment()
                .withProperty("lightning.lnd.enabled", "false")
                .withProperty("app.cors.allowed-origins", "https://app.kerosene.test")
                .withProperty("webauthn.relying-party-id", "app.kerosene.test")
                .withProperty("webauthn.origins", "https://app.kerosene.test")
                .withProperty("shard.attestation.secret", "test")
                .withProperty("kerosene.workload-identity.enabled", "true")
                .withProperty("kerosene.workload-identity.socket", "unix:///run/spire.sock")
                .withProperty("kerosene.workload-identity.own-spiffe-id", "spiffe://test/service/auth")
                .withProperty("kerosene.workload-identity.peer-spiffe-id", "spiffe://test/service/kfe");
        for (String key : java.util.List.of("kfe.vaultmesh.enabled", "bitcoin.rpc.enabled", "bitcoin.rpc.required",
                "bitcoin.rpc.pruned-required", "tor.health.required", "release.attestation.required", "release.attestation.remote.enabled")) {
            environment.withProperty(key, "true");
        }
        environment.setActiveProfiles("prod");
        assertThat(new StartupDiagnosticsService(environment).diagnose().failCount()).isZero();
    }

    private MockEnvironment baseEnvironment() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:postgresql://db:5432/kerosene")
                .withProperty("spring.datasource.username", "api_system")
                .withProperty("spring.datasource.password", "change-me")
                .withProperty("spring.data.redis.host", "redis")
                .withProperty("spring.data.redis.port", "6379")
                .withProperty("kfe.internal.base-url", "https://kfe:8443")
                .withProperty("kfe.remote.base-url", "https://kfe:8443")
                .withProperty("kfe.vaultmesh.enabled", "false")
                .withProperty("kfe.vaultmesh.base-url", "http://127.0.0.1:7701")
                .withProperty("lightning.lnd.enabled", "true")
                .withProperty("lightning.lnd.host", "lnd-bitcoind")
                .withProperty("lightning.lnd.port", "10009")
                .withProperty("lightning.lnd.tls.enabled", "true")
                .withProperty("kfe.receive.bitcoin-core-wallet-address-enabled", "true")
                .withProperty("kfe.network-monitor.enabled", "true")
                .withProperty("transactions.local-derived-address-fallback-enabled", "false")
                .withProperty("transactions.bitcoin-core-wallet-address-enabled", "true")
                .withProperty("spring.flyway.enabled", "true")
                .withProperty("spring.flyway.baseline-on-migrate", "false");
        environment.setActiveProfiles("docker");
        return environment;
    }
}
