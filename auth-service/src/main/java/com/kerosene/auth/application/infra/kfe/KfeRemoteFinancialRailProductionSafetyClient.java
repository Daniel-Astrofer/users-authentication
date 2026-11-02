package com.kerosene.auth.application.infra.kfe;

import com.kerosene.common.financial.operations.FinancialRailProductionSafetyPort;
import com.kerosene.common.security.workload.InternalServiceRestTemplateFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpMethod;
import org.springframework.core.ParameterizedTypeReference;
import java.util.List;

/** Retrieves KFE's production checks over authenticated internal mTLS. */
@Component
public class KfeRemoteFinancialRailProductionSafetyClient extends KfeRemoteClientSupport implements FinancialRailProductionSafetyPort {
    public KfeRemoteFinancialRailProductionSafetyClient(InternalServiceRestTemplateFactory factory,
            @Value("${kfe.remote.health-base-url:${kfe.remote.base-url}}") String baseUrl) {
        super(factory, baseUrl, 2000, 5000);
    }
    @Override public List<String> collectProductionViolations() {
        try {
            var response = restTemplate.exchange(baseUrl + "/internal/kfe/rail-health/production-violations",
                    HttpMethod.GET, internalEntity(), new ParameterizedTypeReference<List<String>>() {});
            return response.getBody() != null ? List.copyOf(response.getBody()) : List.of("KFE production safety response is missing");
        } catch (org.springframework.web.client.RestClientException exception) {
            return List.of("KFE production safety could not be verified over authenticated mTLS");
        }
    }
}
