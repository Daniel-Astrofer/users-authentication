package com.kerosene.admin.controller;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.common.financial.operations.FinancialOperationsAdminPort;
import com.kerosene.platform.health.OperationalHealthService;
import com.kerosene.platform.health.OperationalHealthSnapshot;
import com.kerosene.platform.release.ReleaseManifestService;
import com.kerosene.admin.service.MobileDownloadService;
import com.kerosene.platform.security.AdminRoles;
import com.kerosene.security.vault.VaultMeshHealthService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Aggregates administrative health, financial provider, Vault mesh, release, and mobile information.
 * All routes require the configured ADMIN or OPERATOR role; financial-provider absence is projected
 * as a DOWN response except logs, which return an empty list.
 */
@RestController
@RequestMapping("/api/admin/operations")
@PreAuthorize(AdminRoles.HAS_ADMIN_OR_OPERATOR)
public class AdminOperationsController {

    /** Application-level dependency health aggregator. */
    private final OperationalHealthService operationalHealthService;
    /** Optional KFE adapter for blockchain, Lightning, log, and metric summaries. */
    private final ObjectProvider<FinancialOperationsAdminPort> financialOperationsAdminPort;
    /** Vault mesh cached health service. */
    private final VaultMeshHealthService vaultMeshHealthService;
    /** Release manifest snapshot source. */
    private final ReleaseManifestService releaseManifestService;
    /** Mobile release metadata source. */
    private final MobileDownloadService mobileDownloadService;

    /**
     * Creates the controller with required health/release services and optional financial operations.
     *
     * @param operationalHealthService dependency health aggregator
     * @param financialOperationsAdminPort optional financial provider adapter
     * @param vaultMeshHealthService Vault mesh status provider
     * @param releaseManifestService release manifest provider
     * @param mobileDownloadService mobile release metadata provider
     */
    public AdminOperationsController(
            OperationalHealthService operationalHealthService,
            ObjectProvider<FinancialOperationsAdminPort> financialOperationsAdminPort,
            VaultMeshHealthService vaultMeshHealthService,
            ReleaseManifestService releaseManifestService,
            MobileDownloadService mobileDownloadService) {
        this.operationalHealthService = operationalHealthService;
        this.financialOperationsAdminPort = financialOperationsAdminPort;
        this.vaultMeshHealthService = vaultMeshHealthService;
        this.releaseManifestService = releaseManifestService;
        this.mobileDownloadService = mobileDownloadService;
    }

    /**
     * Returns a combined operational overview with a shared observation timestamp.
     *
     * @return ordered map of dependency health, chain, Lightning, Vault, release, and mobile data
     */
    @GetMapping("/overview")
    public Map<String, Object> overview() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("checkedAt", Instant.now());
        payload.put("health", operationalHealthService.dependencies());
        payload.put("blockchain", blockchain());
        payload.put("lightning", lightning());
        payload.put("vaultMesh", vaultMeshHealthService.snapshot().asMap());
        payload.put("release", releaseManifestService.snapshot());
        payload.put("mobile", mobileDownloadService.releaseInfo());
        return payload;
    }

    /**
     * Returns the detailed health snapshot for configured runtime dependencies.
     *
     * @return dependency status, observed details, and health evaluation timestamps
     */
    @GetMapping("/health")
    public OperationalHealthSnapshot health() {
        return operationalHealthService.dependencies();
    }

    /**
     * Returns Bitcoin Core administrative data or a bounded DOWN projection when the KFE port is absent.
     *
     * @return blockchain summary map
     */
    @GetMapping("/blockchain")
    public Map<String, Object> blockchain() {
        FinancialOperationsAdminPort port = financialOperationsAdminPort.getIfAvailable();
        if (port == null) {
            return financialAdminUnavailable("BITCOIN_CORE_RPC", "KFE financial operations admin port is not configured");
        }
        return port.blockchain();
    }

    /**
     * Returns Lightning administrative data or a bounded DOWN projection when the KFE port is absent.
     *
     * @return Lightning provider summary map
     */
    @GetMapping("/lightning")
    public Map<String, Object> lightning() {
        FinancialOperationsAdminPort port = financialOperationsAdminPort.getIfAvailable();
        if (port == null) {
            return financialAdminUnavailable("LIGHTNING_PROVIDER", "KFE financial operations admin port is not configured");
        }
        return port.lightning();
    }

    /**
     * Returns the current cached Vault mesh health projection.
     *
     * @return mesh status map from the Vault health service
     */
    @GetMapping("/vault-mesh")
    public Map<String, Object> vaultMesh() {
        return vaultMeshHealthService.snapshot().asMap();
    }

    /**
     * Returns the latest application release manifest metadata.
     *
     * @return immutable release snapshot
     */
    @GetMapping("/release")
    public ReleaseManifestService.ReleaseSnapshot release() {
        return releaseManifestService.snapshot();
    }

    /**
     * Returns current mobile application release and download information.
     *
     * @return configured version and distribution metadata
     */
    @GetMapping("/mobile")
    public MobileDownloadService.MobileReleaseInfo mobile() {
        return mobileDownloadService.releaseInfo();
    }

    /**
     * Returns the most recent financial operations log entries.
     *
     * @param limit maximum number requested from the configured KFE adapter
     * @return log entries, or an empty list when the adapter is absent
     */
    @GetMapping("/logs")
    public List<Map<String, Object>> logs(@RequestParam(defaultValue = "50") int limit) {
        FinancialOperationsAdminPort port = financialOperationsAdminPort.getIfAvailable();
        if (port == null) {
            return List.of();
        }
        return port.logs(limit);
    }

    /**
     * Returns KFE metric summaries or a DOWN projection when no financial adapter is configured.
     *
     * @return metrics summary map
     */
    @GetMapping("/metrics")
    public Map<String, Object> metrics() {
        FinancialOperationsAdminPort port = financialOperationsAdminPort.getIfAvailable();
        if (port == null) {
            return financialAdminUnavailable("KFE_METRICS", "KFE financial operations admin port is not configured");
        }
        return port.metrics();
    }

    /**
     * Builds a stable unavailable response for a missing financial operations adapter.
     *
     * @param primarySource provider identifier used by administrative clients
     * @param message operator-facing explanation of missing configuration
     * @return DOWN response with source, current timestamp, and explanatory message
     */
    private Map<String, Object> financialAdminUnavailable(String primarySource, String message) {
        return Map.of(
                "status", "DOWN",
                "primarySource", primarySource,
                "checkedAt", Instant.now(),
                "message", message);
    }
}
