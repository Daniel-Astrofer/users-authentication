package com.kerosene.admin.cell;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BankObservationClientTest {
    @Test void responseBodyHasAByteLimitAndAFiniteDeadline() throws Exception {
        var releaseBody = new java.util.concurrent.CountDownLatch(1);
        var headersSent = new java.util.concurrent.CountDownLatch(1);
        var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/large", exchange -> {
            byte[] body = new byte[BankObservationClient.MAX_BYTES + 1];
            exchange.sendResponseHeaders(200, body.length);
            try { exchange.getResponseBody().write(body); } finally { exchange.close(); }
        });
        server.createContext("/stalled", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().flush();
            headersSent.countDown();
            try { releaseBody.await(5, java.util.concurrent.TimeUnit.SECONDS); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            finally { exchange.close(); }
        });
        server.start();
        try {
            var client = java.net.http.HttpClient.newHttpClient();
            var origin = "http://127.0.0.1:" + server.getAddress().getPort();
            var large = java.net.http.HttpRequest.newBuilder(java.net.URI.create(origin + "/large")).build();
            assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> BankObservationClient.receive(client, large, 3000));
            var stalled = java.net.http.HttpRequest.newBuilder(java.net.URI.create(origin + "/stalled")).build();
            assertThrows(java.util.concurrent.TimeoutException.class,
                    () -> BankObservationClient.receive(client, stalled, 1000));
            assertEquals(0L, headersSent.getCount(), "deadline must also cover a stalled response body");
        } finally {
            releaseBody.countDown();
            server.stop(0);
        }
    }
    @Test void refusesUntrustedOriginsAndMissingMtlsBeforeNetwork() {
        var config = new CellOperationsProperties(); var client = new BankObservationClient(config);
        for (String origin : new String[]{"http://localhost", "https://user:secret@example.invalid", "https://example.invalid/path", "https://example.invalid?query"}) {
            config.bankUrl = origin; assertThrows(Exception.class, client::fetch);
        }
        config.bankUrl = "https://example.invalid"; assertThrows(Exception.class, client::fetch);
    }
}
