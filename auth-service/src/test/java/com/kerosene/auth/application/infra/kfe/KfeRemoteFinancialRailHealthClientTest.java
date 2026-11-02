package com.kerosene.auth.application.infra.kfe;

import org.junit.jupiter.api.Test;
import com.kerosene.common.security.workload.InternalServiceRestTemplateFactory;
import com.kerosene.common.security.workload.WorkloadIdentityProperties;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class KfeRemoteFinancialRailHealthClientTest {

    @Test
    void fetchesCustodyProviderHealthFromKfe() throws Exception {
        KfeRemoteFinancialRailHealthClient client = client();
        MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate(client));
        server.expect(requestTo("http://kfe.test/internal/kfe/rail-health/custody-provider"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"providerName\":\"BITCOIN_CORE\",\"state\":\"AVAILABLE\",\"implementation\":\"Adapter\",\"canRead\":true,\"canReceive\":true,\"canSpend\":true,\"canReconcile\":true,\"network\":\"MAINNET\",\"syncHeight\":0}",
                        MediaType.APPLICATION_JSON));

        var status = client.custodyProviderHealth();

        assertEquals("BITCOIN_CORE", status.providerName());
        assertEquals("Adapter", status.implementation());
        server.verify();
    }

    @Test
    void fetchesExternalRailProvidersFromKfe() throws Exception {
        KfeRemoteFinancialRailHealthClient client = client();
        MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate(client));
        server.expect(requestTo("http://kfe.test/internal/kfe/rail-health/external-providers"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "[{\"providerName\":\"BITCOIN_CORE\",\"state\":\"AVAILABLE\",\"implementation\":\"Onchain\",\"canRead\":true,\"canReceive\":true,\"canSpend\":true,\"canReconcile\":true,\"network\":\"MAINNET\",\"syncHeight\":0}]",
                        MediaType.APPLICATION_JSON));

        var providers = client.activeRailProviderHealth();

        assertEquals("BITCOIN_CORE", providers.get(0).providerName());
        server.verify();
    }

    @Test
    void preservesFailedMeshReadinessFromKfe() throws Exception {
        var client = client();
        var server = MockRestServiceServer.createServer(restTemplate(client));
        server.expect(requestTo("http://kfe.test/internal/kfe/rail-health/vault-mesh"))
                .andRespond(withSuccess("{\"ready\":false,\"status\":\"DOWN:PROBE_STALE\",\"checkedAt\":null}", MediaType.APPLICATION_JSON));
        var mesh = client.vaultMeshHealth();
        assertEquals(false, mesh.ready());
        assertEquals("DOWN:PROBE_STALE", mesh.status());
        server.verify();
    }

    private KfeRemoteFinancialRailHealthClient client() {
        return new KfeRemoteFinancialRailHealthClient(
                new InternalServiceRestTemplateFactory(
                        new WorkloadIdentityProperties().toConfig(), null, "credential"),
                "http://kfe.test",
                100,
                100);
    }

    private RestTemplate restTemplate(KfeRemoteFinancialRailHealthClient client) throws Exception {
        Field field = KfeRemoteClientSupport.class.getDeclaredField("restTemplate");
        field.setAccessible(true);
        return (RestTemplate) field.get(client);
    }
}
