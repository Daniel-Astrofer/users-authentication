package com.kerosene.notification.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kerosene.common.financial.notification.FinancialNotificationEventRequest;
import com.kerosene.common.financial.notification.FinancialNotificationPort;
import com.kerosene.common.financial.notification.FinancialNotificationReceipt;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.time.Instant;
import java.util.UUID;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Controller/wire compatibility. Workload authentication is verified by the security suite. */
class FinancialNotificationHttpContractTest {
    @Test void durableEndpointCannotBeCalledWithOnlyAnAppSessionToken() throws Exception {
        var port = mock(FinancialNotificationPort.class);
        var config = new com.kerosene.common.security.workload.WorkloadIdentityConfig(false,
                "unix:///run/spire.sock", "spiffe://test/service/auth", "spiffe://test/service/kfe",
                8443, java.time.Duration.ofSeconds(1));
        var filter = new com.kerosene.common.security.workload.InternalServiceAuthenticationFilter(
                config, "test-workload-credential", java.util.List.of("/internal/kfe"));
        var mvc = MockMvcBuilders.standaloneSetup(new KfeInternalFinancialNotificationController(port))
                .addFilters(filter).build();
        mvc.perform(post("/internal/kfe/notifications/events")
                        .header("Authorization", "Bearer app-session")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(port);
    }

    @Test void allLegacyLifecycleRoutesExistAndDispatchTheirActualHandlers() throws Exception {
        var port = mock(FinancialNotificationPort.class);
        var mvc = MockMvcBuilders.standaloneSetup(new KfeInternalFinancialNotificationController(port)).build();
        var tx = UUID.randomUUID();
        var wallet = UUID.randomUUID();
        String body = """
                {"userId":42,"transactionId":"%s","walletId":"%s","rail":"ONCHAIN",
                 "amountSats":1500,"confirmations":1,"destinationHint":"PROVIDER_FAILURE"}
                """.formatted(tx, wallet);
        for (String route : new String[]{"payment-initiated", "payment-broadcast", "payment-confirmed",
                "payment-failed", "payment-reconciliation-required", "outbound-conflicted"}) {
            mvc.perform(post("/internal/kfe/notifications/" + route).contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isOk());
        }
        verify(port).notifyPaymentInitiated(42L, tx, wallet, "ONCHAIN", 1500);
        verify(port).notifyPaymentBroadcast(42L, tx, wallet, "ONCHAIN", 1500, "PROVIDER_FAILURE");
        verify(port).notifyPaymentConfirmed(42L, tx, wallet, "ONCHAIN", 1500, 1);
        verify(port).notifyPaymentFailed(42L, tx, wallet, "ONCHAIN", 1500, "PROVIDER_FAILURE", null);
        verify(port).notifyPaymentReconciliationRequired(42L, tx, wallet, "ONCHAIN", 1500, null);
        verify(port).notifyOutboundConflicted(42L, tx, wallet, "ONCHAIN", 1500, "PROVIDER_FAILURE");
    }

    @Test void durableEndpointAcknowledgesTheMatchingIdentityAndRejectsUnsupportedSchema() throws Exception {
        var port = mock(FinancialNotificationPort.class);
        var request = new FinancialNotificationEventRequest(UUID.randomUUID(), 1,
                FinancialNotificationEventRequest.Type.PAYMENT_CONFIRMED, 42L, UUID.randomUUID(), UUID.randomUUID(),
                "ONCHAIN", 1500, 1, null, null, null, null, Instant.parse("2026-10-09T12:00:00Z"), 2);
        when(port.deliverEvent(any())).thenReturn(new FinancialNotificationReceipt(request.eventId(), true));
        var mvc = MockMvcBuilders.standaloneSetup(new KfeInternalFinancialNotificationController(port)).build();
        String body = new ObjectMapper().registerModule(new JavaTimeModule()).writeValueAsString(request);
        mvc.perform(post("/internal/kfe/notifications/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("$.eventId").value(request.eventId().toString()))
                .andExpect(jsonPath("$.accepted").value(true));
        mvc.perform(post("/internal/kfe/notifications/events").contentType(MediaType.APPLICATION_JSON)
                        .content(body.replace("\"schemaVersion\":1", "\"schemaVersion\":2")))
                .andExpect(status().isBadRequest());
        verify(port, times(1)).deliverEvent(any());
    }
}
