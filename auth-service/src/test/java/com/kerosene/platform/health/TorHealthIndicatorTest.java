package com.kerosene.platform.health;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.actuate.health.Status;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TorHealthIndicatorTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldReportUpWhenTorSocketAndVanguardsStateExist() throws Exception {
        Path socks = Files.createFile(tempDir.resolve("tor.sock"));
        Path state = Files.createFile(tempDir.resolve("vanguards.state"));
        Files.writeString(state, "layer2=abc\nlayer3=def\n");

        TorHealthIndicator indicator = new TorHealthIndicator(socks.toString(), state.toString(), true, "", 9050);

        assertEquals(Status.UP, indicator.health().getStatus());
    }

    @Test
    void shouldReportDownWhenVanguardsStateIsMissing() throws Exception {
        Path socks = Files.createFile(tempDir.resolve("tor.sock"));

        TorHealthIndicator indicator = new TorHealthIndicator(
                socks.toString(),
                tempDir.resolve("missing.state").toString(),
                true, "", 9050);

        assertEquals(Status.DOWN, indicator.health().getStatus());
    }

    @Test
    void tcpEndpointRequiresValidSocks5Handshake() throws Exception {
        try (var server = new java.net.ServerSocket(0)) {
            var response = java.util.concurrent.CompletableFuture.runAsync(() -> {
                try (var client = server.accept()) {
                    client.getInputStream().readNBytes(3);
                    client.getOutputStream().write(new byte[] {5, 0});
                } catch (java.io.IOException exception) { throw new java.io.UncheckedIOException(exception); }
            });
            var indicator = new TorHealthIndicator("/unused", "", true, "127.0.0.1", server.getLocalPort());
            assertEquals(Status.UP, indicator.health().getStatus());
            response.get(3, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    @Test
    void tcpEndpointRefusesInvalidProtocol() throws Exception {
        try (var server = new java.net.ServerSocket(0)) {
            var response = java.util.concurrent.CompletableFuture.runAsync(() -> {
                try (var client = server.accept()) {
                    client.getInputStream().readNBytes(3);
                    client.getOutputStream().write(new byte[] {4, 0});
                } catch (java.io.IOException exception) { throw new java.io.UncheckedIOException(exception); }
            });
            var indicator = new TorHealthIndicator("/unused", "", true, "127.0.0.1", server.getLocalPort());
            assertEquals(Status.DOWN, indicator.health().getStatus());
            response.get(3, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    @Test
    void shouldReportUpWhenTorNotRequiredEvenWithoutSocket() {
        TorHealthIndicator indicator = new TorHealthIndicator(
                tempDir.resolve("missing.sock").toString(),
                "",
                false, "", 9050);

        assertEquals(Status.UP, indicator.health().getStatus());
    }
}
