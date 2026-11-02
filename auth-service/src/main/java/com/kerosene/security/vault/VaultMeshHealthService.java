package com.kerosene.security.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.kerosene.common.vaultmesh.governance.VaultMeshDayStatus;
import com.kerosene.common.vaultmesh.settlement.VaultMeshSettlementPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Probes kerosene-vault mesh {@code GET /v1/health} (and day_epoch when the settlement port is present).
 * Replaces HashiCorp Vault Raft / mpc-sidecar as the primary custody health surface under mesh cutover.
 */
@Service
public class VaultMeshHealthService {

    private static final String UP = "UP";
    private static final String DOWN = "DOWN";
    private static final String DEGRADED = "DEGRADED";
    private static final String DISABLED = "DISABLED";

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final ObjectProvider<VaultMeshSettlementPort> settlementPort;
    private final boolean enabled;
    private final boolean meshOnly;
    private final boolean mpcSigningEnabled;
    private final String baseUrl;
    private final String apiToken;

    public VaultMeshHealthService(
            ObjectMapper objectMapper,
            ObjectProvider<VaultMeshSettlementPort> settlementPort,
            @Value("${kfe.vaultmesh.enabled:false}") boolean enabled,
            @Value("${kfe.vaultmesh.mesh-only:false}") boolean meshOnly,
            @Value("${kfe.mpc.signing-enabled:true}") boolean mpcSigningEnabled,
            @Value("${kfe.vaultmesh.base-url:https://127.0.0.1:7801}") String baseUrl,
            @Value("${kfe.vaultmesh.api-token:}") String apiToken) {
        this.objectMapper = objectMapper;
        this.settlementPort = settlementPort;
        this.enabled = enabled;
        this.meshOnly = meshOnly;
        this.mpcSigningEnabled = mpcSigningEnabled;
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.apiToken = apiToken == null ? "" : apiToken.trim();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
    }

    public VaultMeshSnapshot snapshot() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("enabled", enabled);
        details.put("meshOnly", meshOnly);
        details.put("mpcSigningEnabled", mpcSigningEnabled);
        details.put("baseUrl", baseUrl);
        details.put("custodyPath", "kerosene-vault-mesh");
        details.put("governance", "vaults+releases");

        if (!enabled) {
            return new VaultMeshSnapshot(
                    DISABLED,
                    null,
                    null,
                    null,
                    0,
                    null,
                    false,
                    false,
                    Instant.now(),
                    "Vault mesh health check is disabled (kfe.vaultmesh.enabled=false)",
                    details);
        }

        if (meshOnly && mpcSigningEnabled) {
            details.put("goLiveGuard", "FAILED");
            return new VaultMeshSnapshot(
                    DOWN,
                    null,
                    null,
                    null,
                    0,
                    null,
                    false,
                    true,
                    Instant.now(),
                    "mesh-only requires kfe.mpc.signing-enabled=false (no dual-run mpc)",
                    details);
        }

        try {
            JsonNode health = getPublicHealth();
            String nodeId = text(health, "node_id");
            String nodeStatus = text(health, "status");
            String attestationMode = text(health, "attestation_mode");
            String nodeTier = text(health, "node_tier");
            boolean teeAvailable = health.path("tee_available").asBoolean(false);
            int peerCount = health.path("peer_count").asInt(0);
            details.put("nodeStatus", nodeStatus);
            details.put("raw", Map.of(
                    "node_id", nodeId == null ? "" : nodeId,
                    "status", nodeStatus == null ? "" : nodeStatus,
                    "node_tier", nodeTier == null ? "" : nodeTier,
                    "attestation_mode", attestationMode == null ? "" : attestationMode,
                    "tee_available", teeAvailable,
                    "peer_count", peerCount));

            boolean labAttestation = attestationMode != null
                    && ("sim".equalsIgnoreCase(attestationMode) || "simulation".equalsIgnoreCase(attestationMode));
            details.put("labAttestation", labAttestation);
            if (labAttestation) {
                details.put(
                        "attestationHonesty",
                        "attestation_mode=sim — lab visualization only; not hardware TEE quorum");
            } else if (attestationMode != null && "software".equalsIgnoreCase(attestationMode)) {
                details.put(
                        "attestationHonesty",
                        "attestation_mode=software — domestic measurement (not SEV/SGX); TPM≠TEE");
            }

            VaultMeshDayStatus day = probeDayStatus(details);
            String dayEpoch = day == null ? null : day.dayEpoch();
            boolean dayUpToDate = day != null && day.upToDate();
            if (day != null && day.error() != null) {
                details.put("dayError", day.error());
            }
            if (day != null) {
                details.put("dayStale", day.stale());
                details.put("neededDayEpoch", day.neededDayEpoch());
            }

            boolean nodeReady = nodeStatus != null && "ready".equalsIgnoreCase(nodeStatus);
            String status;
            String message;
            if (!nodeReady && nodeStatus != null && "starting".equalsIgnoreCase(nodeStatus)) {
                status = DEGRADED;
                message = "Vault mesh node is starting (peers may still be joining)";
            } else if (!nodeReady) {
                status = DOWN;
                message = "Vault mesh /v1/health did not report ready";
            } else if (labAttestation) {
                status = DEGRADED;
                message = "Vault mesh reachable with lab attestation (sim) — not production TEE";
            } else if (day != null && day.error() != null) {
                status = DEGRADED;
                message = "Vault mesh /v1/health OK; day_epoch probe gap: " + day.error();
            } else if (day != null && day.stale()) {
                status = DEGRADED;
                message = "Vault mesh reachable but day_epoch is stale";
            } else {
                status = UP;
                message = meshOnly
                        ? "Vault mesh healthy (mesh-only; mpc signing off)"
                        : "Vault mesh healthy";
            }

            return new VaultMeshSnapshot(
                    status,
                    nodeId,
                    nodeStatus,
                    attestationMode,
                    peerCount,
                    dayEpoch,
                    dayUpToDate,
                    meshOnly,
                    Instant.now(),
                    message,
                    details);
        } catch (Exception exception) {
            details.put("exception", exception.getClass().getSimpleName());
            details.put("error", safeMessage(exception));
            return new VaultMeshSnapshot(
                    DOWN,
                    null,
                    null,
                    null,
                    0,
                    null,
                    false,
                    meshOnly,
                    Instant.now(),
                    "Vault mesh /v1/health probe failed",
                    details);
        }
    }

    private JsonNode getPublicHealth() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/v1/health"))
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("HTTP " + response.statusCode());
        }
        return objectMapper.readTree(response.body());
    }

    private VaultMeshDayStatus probeDayStatus(Map<String, Object> details) {
        VaultMeshSettlementPort port = settlementPort.getIfAvailable();
        if (port == null) {
            details.put("dayEpochProbe", "settlement-port-unavailable");
            return VaultMeshDayStatus.failed("DAY_PROBE_UNAVAILABLE");
        }
        try {
            return port.getDayStatus();
        } catch (Exception exception) {
            details.put("dayEpochProbe", exception.getClass().getSimpleName());
            return VaultMeshDayStatus.failed("DAY_PROBE_ERROR");
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String text = value.asText(null);
        return text == null || text.isBlank() ? null : text;
    }

    private static String stripTrailingSlash(String value) {
        String trimmed = value != null ? value.trim() : "";
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isEmpty() ? "https://127.0.0.1:7801" : trimmed;
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }
        return message.replaceAll("(?i)(password|secret|token|key)=\\S+", "$1=***MASKED***");
    }

    public record VaultMeshSnapshot(
            String status,
            String nodeId,
            String nodeStatus,
            String attestationMode,
            int peerCount,
            String dayEpoch,
            boolean dayUpToDate,
            boolean meshOnly,
            Instant checkedAt,
            String message,
            Map<String, Object> details) {

        public Map<String, Object> asMap() {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("status", status);
            payload.put("nodeId", nodeId);
            payload.put("nodeStatus", nodeStatus);
            payload.put("attestationMode", attestationMode);
            payload.put("peerCount", peerCount);
            payload.put("dayEpoch", dayEpoch);
            payload.put("dayUpToDate", dayUpToDate);
            payload.put("meshOnly", meshOnly);
            payload.put("checkedAt", checkedAt);
            payload.put("message", message);
            payload.put("details", details);
            // Compatibility aliases used by admin metric cards that previously read Raft fields.
            payload.put("votingServers", peerCount);
            payload.put("expectedServers", details != null && details.get("expectedServers") != null
                    ? details.get("expectedServers")
                    : peerCount);
            return payload;
        }

        public boolean isLabAttestation() {
            return attestationMode != null
                    && attestationMode.toLowerCase(Locale.ROOT).startsWith("sim");
        }
    }
}
