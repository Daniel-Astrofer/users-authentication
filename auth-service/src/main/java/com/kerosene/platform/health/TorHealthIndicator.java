package com.kerosene.platform.health;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class TorHealthIndicator implements HealthIndicator {

    private final Path socksPath;
    private final Path vanguardsStatePath;
    private final boolean required;
    private final String socksHost;
    private final int socksPort;

    public TorHealthIndicator(
            @Value("${tor.health.socks-path:/var/run/tor/socks/tor.sock}") String socksPath,
            @Value("${tor.health.vanguards-state-file:}") String vanguardsStatePath,
            @Value("${tor.health.required:true}") boolean required,
            @Value("${tor.health.socks-host:}") String socksHost,
            @Value("${tor.health.socks-port:9050}") int socksPort) {
        this.socksPath = Path.of(socksPath);
        this.vanguardsStatePath = vanguardsStatePath == null || vanguardsStatePath.isBlank()
                ? null
                : Path.of(vanguardsStatePath);
        this.required = required;
        this.socksHost = socksHost == null ? "" : socksHost.trim();
        this.socksPort = socksPort;
    }

    @Override
    public Health health() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("required", required);

        // Local-full / onion-gateway-only: Tor runs in a separate pod; SOCKS is not
        // mounted into server/KFE. Actuator readiness includes this indicator, so when
        // tor is not required we must not report DOWN and fail /actuator/health.
        if (!required) {
            details.put("reason", "Tor health is not required for this profile");
            Health.Builder builder = Health.up();
            details.forEach(builder::withDetail);
            return builder.build();
        }

        boolean torSocketReady = socksHost.isBlank()
                ? Files.exists(socksPath) && Files.isReadable(socksPath)
                : tcpSocksReady();
        if (!socksHost.isBlank()) details.put("torSocksHost", socksHost);
        details.put("torSocksPath", socksPath.toString());
        details.put("torSocksReady", torSocketReady);

        boolean vanguardsReady = true;
        if (vanguardsStatePath != null) {
            vanguardsReady = Files.isRegularFile(vanguardsStatePath) && Files.isReadable(vanguardsStatePath);
            details.put("vanguardsStateFile", vanguardsStatePath.toString());
            details.put("vanguardsStateReady", vanguardsReady);
            if (vanguardsReady) {
                details.put("vanguardsStateSizeBytes", readFileSize(vanguardsStatePath));
                details.put("vanguardsStateLastModified", readLastModified(vanguardsStatePath));
            }
        }

        Health.Builder builder = torSocketReady && vanguardsReady ? Health.up() : Health.down();
        details.forEach(builder::withDetail);
        if (!torSocketReady) {
            builder.withDetail("reason", "Tor SOCKS endpoint unavailable or invalid");
        }
        if (torSocketReady && !vanguardsReady) {
            builder.withDetail("reason", "Tor is up but Vanguards state is missing or unreadable");
        }
        return builder.build();
    }

    private boolean tcpSocksReady() {
        try (var socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(socksHost, socksPort), 2000);
            socket.setSoTimeout(2000);
            socket.getOutputStream().write(new byte[] {5, 1, 0});
            return socket.getInputStream().read() == 5 && socket.getInputStream().read() == 0;
        } catch (IOException exception) {
            return false;
        }
    }

    private static long readFileSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException ignored) {
            return -1L;
        }
    }

    private static String readLastModified(Path path) {
        try {
            FileTime fileTime = Files.getLastModifiedTime(path);
            return fileTime.toString();
        } catch (IOException ignored) {
            return "unknown";
        }
    }
}
