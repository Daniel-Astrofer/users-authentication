package com.kerosene.admin.cell;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.stereotype.Component;

/** Fixed operator-configured origin; caller input never chooses an upstream. */
@Component
public class BankObservationClient {
    static final int MAX_BYTES = 1_048_576;
    private final CellOperationsProperties config;
    public BankObservationClient(CellOperationsProperties config) { this.config = config; }

    public byte[] fetch() throws Exception {
        if (!config.targetReleaseDigest.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalStateException("BANK_TARGET_DIGEST_NOT_CONFIGURED");
        }
        return fetch(config.bankUrl, "/v1/releases/observations?releaseDigest="
                + java.net.URLEncoder.encode(config.targetReleaseDigest, java.nio.charset.StandardCharsets.UTF_8), null);
    }

    byte[] fetch(String origin, String path, String token) throws Exception {
        URI base = URI.create(origin);
        if (!"https".equals(base.getScheme()) || base.getHost() == null || base.getUserInfo() != null
                || base.getQuery() != null || base.getFragment() != null
                || !(base.getPath().isEmpty() || base.getPath().equals("/"))) {
            throw new IllegalStateException("BANK_HTTPS_ORIGIN_REQUIRED");
        }
        if (config.keyStore.isBlank() || config.trustStore.isBlank()) {
            throw new IllegalStateException("BANK_MTLS_NOT_CONFIGURED");
        }
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        char[] keyPassword = config.keyStorePassword.toCharArray();
        char[] trustPassword = config.trustStorePassword.toCharArray();
        try {
            KeyStore keys = load(config.keyStore, keyPassword);
            if (java.util.Collections.list(keys.aliases()).stream().noneMatch(alias -> {
                try { return keys.isKeyEntry(alias); } catch (Exception e) { return false; }
            })) throw new IllegalStateException("BANK_CLIENT_KEY_MISSING");
            var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            km.init(keys, keyPassword);
            var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tm.init(load(config.trustStore, trustPassword));
            tls.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        } finally {
            Arrays.fill(keyPassword, '\0');
            Arrays.fill(trustPassword, '\0');
        }
        var client = HttpClient.newBuilder().sslContext(tls).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        var builder = HttpRequest.newBuilder(base.resolve(path))
                .timeout(Duration.ofSeconds(10)).header("Accept", "application/json");
        if (token != null) builder.header("Authorization", "Bearer " + token);
        var request = builder.GET().build();
        return receive(client, request, 10_000);
    }

    /** Bounds the complete response, including a peer that sends headers then stalls the body. */
    static byte[] receive(HttpClient client, HttpRequest request, long timeoutMillis) throws Exception {
        var pending = client.sendAsync(request, ignored -> new BoundedBody());
        try {
            var response = pending.get(timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
            if (response.statusCode() != 200) throw new IllegalStateException("BANK_UNAVAILABLE");
            return response.body();
        } catch (InterruptedException interrupted) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw interrupted;
        } catch (Exception failure) {
            pending.cancel(true);
            throw failure;
        }
    }

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private java.util.concurrent.Flow.Subscription subscription;
        private long received;
        public java.util.concurrent.CompletionStage<byte[]> getBody() { return delegate.getBody(); }
        public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) {
            this.subscription = subscription;
            delegate.onSubscribe(subscription);
        }
        public void onNext(java.util.List<java.nio.ByteBuffer> buffers) {
            for (var buffer : buffers) {
                received += buffer.remaining();
                if (received > MAX_BYTES) {
                    subscription.cancel();
                    delegate.onError(new IllegalStateException("BANK_RESPONSE_TOO_LARGE"));
                    return;
                }
            }
            delegate.onNext(buffers);
        }
        public void onError(Throwable failure) { delegate.onError(failure); }
        public void onComplete() { delegate.onComplete(); }
    }

    private KeyStore load(String file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(Path.of(file))) { store.load(input, password); }
        return store;
    }
}
