package com.kerosene.platform.health;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.StringRedisTemplate;
import com.kerosene.platform.config.production.ProductionProfileDetector;
import com.kerosene.platform.config.production.ProductionSafetyCheckChain;
import com.kerosene.common.financial.operations.FinancialRailHealthPort;

import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DatabaseMetaData;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class OperationalHealthService {

    private static final String UP = "UP";
    private static final String DOWN = "DOWN";
    private static final String DEGRADED = "DEGRADED";
    private static final String UNKNOWN = "UNKNOWN";
    private static final String DISABLED = "DISABLED";

    private static final List<String> REQUIRED_CONFIG = List.of(
            "spring.datasource.url",
            "spring.datasource.username",
            "spring.data.redis.host",
            "api.secret.aes.secret",
            "api.secret.token.secret",
            "api.secret.pepper.secret");

    private static final List<TableRef> REQUIRED_TABLES = List.of(
            new TableRef("auth", "users_credentials"),
            new TableRef("auth", "passkey_credentials"),
            new TableRef("public", "notifications"));

    private final JdbcTemplate jdbcTemplate;
    private final StringRedisTemplate redisTemplate;
    private final ApplicationAvailability applicationAvailability;
    private final Environment environment;
    private final ObjectProvider<TorHealthIndicator> torHealthIndicator;
    private final ObjectProvider<FinancialRailHealthPort> financialRailHealthPort;
    private final ProductionProfileDetector productionProfileDetector;
    private final ProductionSafetyCheckChain productionSafetyCheckChain;
    private final HealthMetricRecorder metricRecorder;
    private final String applicationName;

    public OperationalHealthService(
            JdbcTemplate jdbcTemplate,
            StringRedisTemplate redisTemplate,
            ApplicationAvailability applicationAvailability,
            Environment environment,
            ObjectProvider<TorHealthIndicator> torHealthIndicator,
            ObjectProvider<FinancialRailHealthPort> financialRailHealthPort,
            ProductionProfileDetector productionProfileDetector,
            ProductionSafetyCheckChain productionSafetyCheckChain,
            HealthMetricRecorder metricRecorder,
            @Value("${spring.application.name:kerosene}") String applicationName) {
        this.jdbcTemplate = jdbcTemplate;
        this.redisTemplate = redisTemplate;
        this.applicationAvailability = applicationAvailability;
        this.environment = environment;
        this.torHealthIndicator = torHealthIndicator;
        this.financialRailHealthPort = financialRailHealthPort;
        this.productionProfileDetector = productionProfileDetector;
        this.productionSafetyCheckChain = productionSafetyCheckChain;
        this.metricRecorder = metricRecorder;
        this.applicationName = applicationName;
    }

    public OperationalHealthSnapshot liveness() {
        Map<String, DependencyHealth> checks = new LinkedHashMap<>();
        checks.put("process", checkProcess());
        return snapshot(aggregate(checks, true), checks);
    }

    public OperationalHealthSnapshot readiness() {
        Map<String, DependencyHealth> checks = new LinkedHashMap<>();
        checks.put("applicationAvailability", checkReadinessState());
        checks.put("configuration", checkConfiguration(true));
        checks.put("database", checkDatabase(true));
        checks.put("schema", checkSchema(true));
        checks.put("redis", checkRedis(true));
        putCustodyChecks(checks);
        checks.put("tor", checkTor(torRequired()));
        checks.put("lightning", checkLightning(lightningRequired()));
        checks.put("storage", checkStorage(storageRequired()));
        return snapshot(aggregate(checks, true), checks);
    }

    public OperationalHealthSnapshot publicReadiness() {
        return withoutDetails(readiness());
    }

    public OperationalHealthSnapshot dependencies() {
        Map<String, DependencyHealth> checks = new LinkedHashMap<>();
        checks.put("database", checkDatabase(true));
        checks.put("schema", checkSchema(true));
        checks.put("redis", checkRedis(true));
        checks.put("configuration", checkConfiguration(true));
        putCustodyChecks(checks);
        checks.put("tor", checkTor(torRequired()));
        checks.put("lightning", checkLightning(lightningRequired()));
        checks.put("bitcoinProvider", checkBitcoinProvider(false));
        checks.put("mempoolProvider", checkMempoolProvider(false));
        checks.put("custodyProvider", checkCustodyProvider(false));
        checks.put("externalRailProviders", checkExternalRailProviders(false));
        checks.put("queues", checkQueues(false));
        checks.put("storage", checkStorage(storageRequired()));
        checks.put("authProvider", checkAuthProvider(true));
        return snapshot(aggregate(checks, false), checks);
    }

    /**
     * Custody governance health is vault-mesh only ({@code GET /v1/health}).
     * HashiCorp Vault / Raft / mpc-sidecar are not part of readiness or admin health aggregation.
     */
    private void putCustodyChecks(Map<String, DependencyHealth> checks) {
        boolean meshEnabled = vaultMeshEnabled();
        // Optional when mesh is off (lab without vaultmesh); critical when enabled/mesh-only.
        checks.put("vaultMesh", checkVaultMesh(meshEnabled || vaultMeshOnly()));
    }

    private DependencyHealth checkProcess() {
        long start = System.nanoTime();
        LivenessState state = applicationAvailability.getLivenessState();
        boolean up = state != LivenessState.BROKEN;
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("livenessState", state.toString());
        details.put("uptimeMs", java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime());
        return record(new DependencyHealth(
                "process",
                up ? UP : DOWN,
                true,
                elapsedMs(start),
                up ? "HTTP thread is serving requests" : "Spring liveness state is BROKEN",
                details));
    }

    private DependencyHealth checkReadinessState() {
        long start = System.nanoTime();
        ReadinessState state = applicationAvailability.getReadinessState();
        boolean up = state == ReadinessState.ACCEPTING_TRAFFIC;
        return record(new DependencyHealth(
                "applicationAvailability",
                up ? UP : DOWN,
                true,
                elapsedMs(start),
                up ? "Spring availability accepts traffic" : "Spring availability refuses traffic",
                Map.of("readinessState", state.toString())));
    }

    private DependencyHealth checkDatabase(boolean critical) {
        long start = System.nanoTime();
        try {
            Integer one = jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            boolean up = one != null && one == 1;
            return record(new DependencyHealth(
                    "database",
                    up ? UP : DOWN,
                    critical,
                    elapsedMs(start),
                    up ? "Primary relational database answered SELECT 1" : "Unexpected database probe result",
                    Map.of("probe", "select_1")));
        } catch (Exception exception) {
            return record(down("database", critical, start, "Primary relational database is unavailable", exception));
        }
    }

    private DependencyHealth checkSchema(boolean critical) {
        long start = System.nanoTime();
        try {
            List<String> missing = jdbcTemplate.execute((ConnectionCallback<List<String>>) connection -> {
                DatabaseMetaData metaData = connection.getMetaData();
                List<String> notFound = new java.util.ArrayList<>();
                for (TableRef table : REQUIRED_TABLES) {
                    try (var tables = metaData.getTables(null, table.schema(), table.name(), new String[] { "TABLE" })) {
                        if (!tables.next()) {
                            notFound.add(table.schema() + "." + table.name());
                        }
                    }
                }
                return notFound;
            });

            boolean up = missing == null || missing.isEmpty();
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("migrationMode", "flyway_plus_hibernate_validate");
            details.put("requiredTablesChecked", REQUIRED_TABLES.size());
            if (!up) {
                details.put("missingTables", missing);
            }
            return record(new DependencyHealth(
                    "schema",
                    up ? UP : DOWN,
                    critical,
                    elapsedMs(start),
                    up ? "Required database schema objects are present" : "Database schema is missing required objects",
                    details));
        } catch (Exception exception) {
            return record(down("schema", critical, start, "Could not validate database schema state", exception));
        }
    }

    private DependencyHealth checkRedis(boolean critical) {
        long start = System.nanoTime();
        try {
            String pong = redisTemplate.execute(
                    (org.springframework.data.redis.core.RedisCallback<String>) connection -> connection.ping());
            boolean up = "PONG".equalsIgnoreCase(pong);
            return record(new DependencyHealth(
                    "redis",
                    up ? UP : DOWN,
                    critical,
                    elapsedMs(start),
                    up ? "Redis answered PING" : "Redis did not answer PONG",
                    Map.of("probe", "ping")));
        } catch (Exception exception) {
            return record(down("redis", critical, start, "Redis is unavailable", exception));
        }
    }

    private DependencyHealth checkConfiguration(boolean critical) {
        long start = System.nanoTime();
        List<String> missing = REQUIRED_CONFIG.stream()
                .filter(property -> isBlankOrUnresolved(environment.getProperty(property)))
                .toList();
        List<String> productionViolations = productionProfileDetector.isProductionProfile()
                ? productionSafetyCheckChain.collectViolations()
                : List.of();

        boolean up = missing.isEmpty() && productionViolations.isEmpty();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("activeProfiles", Arrays.asList(environment.getActiveProfiles()));
        if (!missing.isEmpty()) {
            details.put("missingRequiredProperties", missing);
        }
        if (!productionViolations.isEmpty()) {
            details.put("productionSafetyViolations", productionViolations);
        }

        return record(new DependencyHealth(
                "configuration",
                up ? UP : DOWN,
                critical,
                elapsedMs(start),
                up ? "Essential runtime configuration is loaded" : "Essential runtime configuration is incomplete",
                details));
    }


    private DependencyHealth checkVaultMesh(boolean critical) {
        long start = System.nanoTime();
        try {
            FinancialRailHealthPort port = financialRailHealthPort.getIfAvailable();
            var mesh = port != null ? port.vaultMeshHealth() : null;
            boolean ready = mesh != null && mesh.ready();
            return record(new DependencyHealth("vaultMesh", ready ? UP : DOWN, critical,
                    elapsedMs(start), "KFE authenticated Vault Mesh readiness",
                    Map.of("status", mesh != null ? mesh.status() : "UNAVAILABLE")));
        } catch (Exception exception) {
            return record(down("vaultMesh", critical, start, "KFE Vault Mesh readiness unavailable", exception));
        }
    }

    private DependencyHealth checkTor(boolean critical) {
        long start = System.nanoTime();
        if (!critical) {
            return record(new DependencyHealth(
                    "tor",
                    UP,
                    false,
                    elapsedMs(start),
                    "Tor health is not required for this profile",
                    Map.of("required", false)));
        }

        try {
            var health = torHealthIndicator.getObject().health();
            boolean up = org.springframework.boot.actuate.health.Status.UP.equals(health.getStatus());
            Map<String, Object> details = new LinkedHashMap<>(health.getDetails());
            details.put("required", true);
            return record(new DependencyHealth(
                    "tor",
                    up ? UP : DOWN,
                    true,
                    elapsedMs(start),
                    up ? "Tor and Vanguards are ready" : "Tor or Vanguards are not ready",
                    details));
        } catch (Exception exception) {
            return record(down("tor", true, start, "Tor health probe failed", exception));
        }
    }

    private DependencyHealth checkLightning(boolean critical) {
        long start = System.nanoTime();
        boolean enabled = lightningEnabled();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("enabled", enabled);
        if (!enabled) {
            return record(new DependencyHealth(
                    "lightning",
                    UP,
                    critical,
                    elapsedMs(start),
                    "Lightning/LND is disabled for this profile",
                    details));
        }

        String host = environment.getProperty("lightning.lnd.host", "");
        int port = environment.getProperty("lightning.lnd.port", Integer.class, 10009);
        details.put("host", host);
        details.put("port", port);
        if (!hasText(host)) {
            return record(new DependencyHealth(
                    "lightning",
                    DOWN,
                    critical,
                    elapsedMs(start),
                    "LND host is not configured",
                    details));
        }

        boolean macaroonConfigured = hasText(environment.getProperty("lightning.lnd.macaroon"))
                || isReadableFile(environment.getProperty("lightning.lnd.macaroon-path"));
        details.put("macaroonConfigured", macaroonConfigured);
        if (!macaroonConfigured) {
            return record(new DependencyHealth(
                    "lightning",
                    DOWN,
                    critical,
                    elapsedMs(start),
                    "LND macaroon is not configured or readable",
                    details));
        }

        if (environment.getProperty("lightning.lnd.tls.enabled", Boolean.class, true)
                && !isReadableFile(environment.getProperty("lightning.lnd.tls.cert-path"))) {
            return record(new DependencyHealth(
                    "lightning",
                    DOWN,
                    critical,
                    elapsedMs(start),
                    "LND TLS certificate is not readable",
                    details));
        }

        boolean up = tcpConnects(host, port, Duration.ofSeconds(2));
        return record(new DependencyHealth(
                "lightning",
                up ? UP : DOWN,
                critical,
                elapsedMs(start),
                up ? "LND endpoint is reachable" : "LND endpoint is unreachable",
                details));
    }

    private DependencyHealth checkStorage(boolean critical) {
        long start = System.nanoTime();
        String identityPath = environment.getProperty("shard.identity.path", "");
        if (!hasText(identityPath)) {
            return record(new DependencyHealth(
                    "storage",
                    UP,
                    critical,
                    elapsedMs(start),
                    "No shard identity storage path is configured for this profile",
                    Map.of("configured", false)));
        }

        Path path = Path.of(identityPath);
        boolean ready = Files.isDirectory(path) && Files.isReadable(path) && Files.isWritable(path);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("path", path.toString());
        details.put("readable", Files.isReadable(path));
        details.put("writable", Files.isWritable(path));
        return record(new DependencyHealth(
                "storage",
                ready ? UP : DOWN,
                critical,
                elapsedMs(start),
                ready ? "Shard identity storage is readable and writable" : "Shard identity storage is not ready",
                details));
    }

    private DependencyHealth checkBitcoinProvider(boolean critical) {
        long start = System.nanoTime();
        boolean rpcEnabled = environment.getProperty("bitcoin.rpc.enabled", Boolean.class, false);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("network", environment.getProperty("bitcoin.network", "mainnet"));
        details.put("rpcEnabled", rpcEnabled);
        if (rpcEnabled) {
            String rpcUrl = environment.getProperty("bitcoin.rpc.url", "");
            details.put("provider", "bitcoin-core-rpc");
            details.put("endpointConfigured", hasText(rpcUrl));
            boolean up = hasText(rpcUrl) && tcpConnects(rpcUrl, Duration.ofSeconds(2));
            return record(new DependencyHealth(
                    "bitcoinProvider",
                    up ? UP : DOWN,
                    critical,
                    elapsedMs(start),
                    up ? "Bitcoin Core RPC endpoint is reachable" : "Bitcoin Core RPC endpoint is unreachable or not configured",
                    details));
        }

        details.put("provider", "esplora-http");
        if (!externalChecksEnabled()) {
            details.put("remoteCheckSkipped", true);
            return record(new DependencyHealth(
                    "bitcoinProvider",
                    UNKNOWN,
                    critical,
                    elapsedMs(start),
                    "Remote Esplora check is disabled; provider is configuration-only",
                    details));
        }

        String url = environment.getProperty("bitcoin.esplora.base-url", "");
        if (!hasText(url)) {
            details.put("endpointConfigured", false);
            return record(new DependencyHealth(
                    "bitcoinProvider",
                    UNKNOWN,
                    critical,
                    elapsedMs(start),
                    "Esplora endpoint is not configured",
                    details));
        }
        boolean up = httpGet2xx(url + "/blocks/tip/height", Duration.ofSeconds(3));
        details.put("remoteCheck", "blocks_tip_height");
        return record(new DependencyHealth(
                "bitcoinProvider",
                up ? UP : DOWN,
                critical,
                elapsedMs(start),
                up ? "Esplora endpoint answered" : "Esplora endpoint did not answer successfully",
                details));
    }

    private DependencyHealth checkMempoolProvider(boolean critical) {
        long start = System.nanoTime();
        String url = environment.getProperty(
                "operational.health.mempool-url",
                "");
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("remoteCheckEnabled", externalChecksEnabled());
        if (!externalChecksEnabled()) {
            return record(new DependencyHealth(
                    "mempoolProvider",
                    UNKNOWN,
                    critical,
                    elapsedMs(start),
                    "Remote mempool check is disabled",
                    details));
        }
        if (!hasText(url)) {
            details.put("endpointConfigured", false);
            return record(new DependencyHealth(
                    "mempoolProvider",
                    UNKNOWN,
                    critical,
                    elapsedMs(start),
                    "Mempool fee endpoint is not configured",
                    details));
        }

        boolean up = httpGet2xx(url, Duration.ofSeconds(3));
        return record(new DependencyHealth(
                "mempoolProvider",
                up ? UP : DOWN,
                critical,
                elapsedMs(start),
                up ? "Mempool fee provider answered" : "Mempool fee provider did not answer successfully",
                details));
    }

    private DependencyHealth checkCustodyProvider(boolean critical) {
        long start = System.nanoTime();
        try {
            FinancialRailHealthPort healthPort = financialRailHealthPort.getIfAvailable();
            if (healthPort == null) {
                return record(new DependencyHealth(
                        "custodyProvider",
                        UNKNOWN,
                        critical,
                        elapsedMs(start),
                        "No financial rail health port is available",
                        Map.of()));
            }
            FinancialRailHealthPort.ProviderHealth status = healthPort.custodyProviderHealth();
            if (status == null) {
                return record(new DependencyHealth(
                        "custodyProvider",
                        UNKNOWN,
                        critical,
                        elapsedMs(start),
                        "No custody provider bean is available",
                        Map.of()));
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("provider", status.providerName());
            details.put("implementation", status.implementation());
            boolean isLive = status.state() == FinancialRailHealthPort.HealthState.AVAILABLE;
            return record(new DependencyHealth(
                    "custodyProvider",
                    isLive ? UP : UNKNOWN,
                    critical,
                    elapsedMs(start),
                    isLive ? "Custody provider is configured as live" : "Custody provider is not configured as live",
                    details));
        } catch (Exception exception) {
            return record(down("custodyProvider", critical, start, "Custody provider probe failed", exception));
        }
    }

    private DependencyHealth checkExternalRailProviders(boolean critical) {
        long start = System.nanoTime();
        try {
            FinancialRailHealthPort healthPort = financialRailHealthPort.getIfAvailable();
            if (healthPort == null) {
                return record(new DependencyHealth(
                        "externalRailProviders",
                        UNKNOWN,
                        critical,
                        elapsedMs(start),
                        "Financial rail health port is not available",
                        Map.of()));
            }
            List<FinancialRailHealthPort.ProviderHealth> providers = healthPort.activeRailProviderHealth();
            if (providers.isEmpty()) {
                return record(new DependencyHealth(
                        "externalRailProviders",
                        UNKNOWN,
                        critical,
                        elapsedMs(start),
                        "External rail provider registry is not available",
                        Map.of()));
            }
            Map<String, Object> details = new LinkedHashMap<>();
            boolean allLive = true;
            for (FinancialRailHealthPort.ProviderHealth status : providers) {
                boolean isLive = status.state() == FinancialRailHealthPort.HealthState.AVAILABLE;
                Map<String, Object> providerDetails = new LinkedHashMap<>();
                providerDetails.put("provider", status.providerName());
                providerDetails.put("implementation", status.implementation());
                providerDetails.put("live", isLive);
                details.put(status.providerName(), providerDetails);
                allLive = allLive && isLive;
            }
            return record(new DependencyHealth(
                    "externalRailProviders",
                    allLive ? UP : DEGRADED,
                    critical,
                    elapsedMs(start),
                    allLive ? "External rail providers are selected and live" : "One or more external rail providers are not live",
                    details));
        } catch (Exception exception) {
            return record(down("externalRailProviders", critical, start, "External rail provider report failed", exception));
        }
    }

    private DependencyHealth checkQueues(boolean critical) {
        long start = System.nanoTime();
        return record(new DependencyHealth(
                "queues",
                UP,
                critical,
                elapsedMs(start),
                "Application uses Spring in-memory WebSocket queues; no external queue dependency configured",
                Map.of("broker", "spring-simple-broker")));
    }

    private DependencyHealth checkAuthProvider(boolean critical) {
        long start = System.nanoTime();
        List<String> missing = List.of(
                        "api.secret.token.secret",
                        "webauthn.relying-party-id",
                        "webauthn.origins")
                .stream()
                .filter(property -> isBlankOrUnresolved(environment.getProperty(property)))
                .toList();
        boolean up = missing.isEmpty();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("mode", "internal-jwt-webauthn");
        if (!missing.isEmpty()) {
            details.put("missingRequiredProperties", missing);
        }
        return record(new DependencyHealth(
                "authProvider",
                up ? UP : DOWN,
                critical,
                elapsedMs(start),
                up ? "Internal authentication configuration is present" : "Internal authentication configuration is incomplete",
                details));
    }

    private OperationalHealthSnapshot snapshot(String status, Map<String, DependencyHealth> checks) {
        return new OperationalHealthSnapshot(
                status,
                applicationName,
                environment.getProperty("REGION", "DEV"),
                Instant.now(),
                checks);
    }

    private OperationalHealthSnapshot withoutDetails(OperationalHealthSnapshot snapshot) {
        Map<String, DependencyHealth> sanitized = new LinkedHashMap<>();
        snapshot.checks().forEach((key, value) -> sanitized.put(key, new DependencyHealth(
                value.name(),
                value.status(),
                value.critical(),
                value.latencyMs(),
                value.message(),
                Map.of())));
        return new OperationalHealthSnapshot(
                snapshot.status(),
                snapshot.service(),
                snapshot.region(),
                snapshot.timestamp(),
                sanitized);
    }

    private String aggregate(Map<String, DependencyHealth> checks, boolean criticalOnly) {
        boolean hasDown = checks.values().stream()
                .anyMatch(check -> check.isDown() && (!criticalOnly || check.critical()));
        if (hasDown) {
            return DOWN;
        }
        boolean hasDegraded = checks.values().stream()
                .anyMatch(check -> (DEGRADED.equals(check.status()) || UNKNOWN.equals(check.status()))
                        && (!criticalOnly || check.critical()));
        return hasDegraded ? DEGRADED : UP;
    }

    private DependencyHealth down(String name, boolean critical, long start, String message, Exception exception) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("errorType", exception.getClass().getSimpleName());
        details.put("error", safeMessage(exception));
        return new DependencyHealth(name, DOWN, critical, elapsedMs(start), message, details);
    }

    private DependencyHealth record(DependencyHealth health) {
        metricRecorder.record(health);
        return health;
    }

    private boolean torRequired() {
        return environment.getProperty(
                "tor.health.required",
                Boolean.class,
                hasProfile("docker") || productionProfileDetector.isProductionProfile());
    }

    private boolean storageRequired() {
        return hasText(environment.getProperty("shard.identity.path"));
    }

    private boolean lightningRequired() {
        return lightningEnabled();
    }

    private boolean lightningEnabled() {
        return environment.getProperty("lightning.lnd.enabled", Boolean.class, false);
    }


    private boolean vaultMeshEnabled() {
        return environment.getProperty("kfe.vaultmesh.enabled", Boolean.class, false);
    }

    private boolean vaultMeshOnly() {
        return environment.getProperty("kfe.vaultmesh.mesh-only", Boolean.class, false);
    }


    private boolean externalChecksEnabled() {
        return environment.getProperty("operational.health.external-checks.enabled", Boolean.class, false);
    }

    private boolean hasProfile(String profile) {
        return Arrays.stream(environment.getActiveProfiles()).anyMatch(profile::equalsIgnoreCase);
    }

    private boolean tcpConnects(String host, int port, Duration timeout) {
        if (!hasText(host) || port <= 0) {
            return false;
        }
        try (var socket = new java.net.Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.toIntExact(timeout.toMillis()));
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean tcpConnects(String url, Duration timeout) {
        try {
            URI uri = URI.create(url);
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return tcpConnects(uri.getHost(), port, timeout);
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean httpGet2xx(String url, Duration timeout) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(Math.toIntExact(timeout.toMillis()));
            connection.setReadTimeout(Math.toIntExact(timeout.toMillis()));
            connection.setRequestMethod("GET");
            connection.setInstanceFollowRedirects(false);
            int status = connection.getResponseCode();
            return status >= 200 && status < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isReadableFile(String value) {
        if (!hasText(value)) {
            return false;
        }
        try {
            Path path = Path.of(value);
            return Files.isRegularFile(path) && Files.isReadable(path);
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isBlankOrUnresolved(String value) {
        return !hasText(value) || value.contains("${");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String safeMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }
        return message.replaceAll("(?i)(password|secret|token|key|macaroon)=\\S+", "$1=***MASKED***");
    }

    private long elapsedMs(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos).toMillis();
    }

    private record TableRef(String schema, String name) {
    }
}
