package com.kerosene.auth.application.infra.kfe;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import com.kerosene.common.security.workload.InternalServiceRestTemplateFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import com.kerosene.common.financial.operations.FinancialRailHealthPort;

import java.util.List;

/** Fetches internal custody and external-provider health projections from KFE. */
@Component
@Profile("!kfe")
@ConditionalOnProperty(name = "kfe.remote.rail-health.enabled", havingValue = "true", matchIfMissing = true)
public class KfeRemoteFinancialRailHealthClient extends KfeRemoteClientSupport implements FinancialRailHealthPort {

    /** Captured generic response type for the provider health list. */
    private static final ParameterizedTypeReference<List<ProviderHealth>> PROVIDER_LIST_TYPE =
            new ParameterizedTypeReference<List<ProviderHealth>>() {};

    /**
     * Creates the client with shared KFE transport settings and internal authentication.
     *
     * @param restTemplateFactory factory configuring internal service HTTP clients
     * @param baseUrl KFE service root
     * @param connectTimeoutMs connection timeout
     * @param readTimeoutMs response timeout
     */
    public KfeRemoteFinancialRailHealthClient(
            InternalServiceRestTemplateFactory restTemplateFactory,
            @Value("${kfe.remote.health-base-url:${kfe.remote.base-url:http://kfe-service:8080}}") String baseUrl,
            @Value("${kfe.remote.connect-timeout-ms:2000}") long connectTimeoutMs,
            @Value("${kfe.remote.read-timeout-ms:5000}") long readTimeoutMs) {
        super(restTemplateFactory, baseUrl, connectTimeoutMs, readTimeoutMs);
    }

    /**
     * Retrieves the configured custody provider health snapshot.
     *
     * @return custody provider health, or null when the successful response has no body
     */
    @Override
    public ProviderHealth custodyProviderHealth() {
        ResponseEntity<ProviderHealth> response = restTemplate.exchange(
                baseUrl + "/internal/kfe/rail-health/custody-provider",
                HttpMethod.GET,
                internalEntity(),
                ProviderHealth.class);
        return response.getBody();
    }

    @Override
    public MeshHealth vaultMeshHealth() {
        return restTemplate.exchange(baseUrl + "/internal/kfe/rail-health/vault-mesh",
                HttpMethod.GET, internalEntity(), MeshHealth.class).getBody();
    }

    /**
     * Retrieves health status for all configured external financial rail providers.
     *
     * @return provider list, normalized to empty when the successful response has no body
     */
    @Override
    public List<ProviderHealth> activeRailProviderHealth() {
        ResponseEntity<List<ProviderHealth>> response = restTemplate.exchange(
                baseUrl + "/internal/kfe/rail-health/external-providers",
                HttpMethod.GET,
                internalEntity(),
                PROVIDER_LIST_TYPE);
        List<ProviderHealth> body = response.getBody();
        return body != null ? body : List.of();
    }
}
