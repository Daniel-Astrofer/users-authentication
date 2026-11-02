package com.kerosene.platform.release;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReleaseAttestationFilterTest {

    private static final String DIGEST = "sha256:manifest";
    private static final String SECRET = "test-secret";

    @Test
    void allowsCriticalRequestWhenDigestAndProofMatch() throws Exception {
        ReleaseAttestationFilter filter = filter(releaseManifestService(true, DIGEST));
        MockHttpServletRequest request = request(DIGEST);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    @Test
    void rejectsCriticalRequestWhenRemoteDigestDiffers() throws Exception {
        ReleaseAttestationFilter filter = filter(releaseManifestService(true, DIGEST));
        MockHttpServletRequest request = request("sha256:other");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertEquals("{\"success\":false,\"error\":\"REMOTE_RELEASE_DIGEST_MISMATCH\"}", response.getContentAsString());
    }

    @Test
    void defaultCriticalPrefixesProtectKfeAdminRoutesNotLegacyAuditSiphon() throws Exception {
        ReleaseAttestationFilter filter = filterWithDefaultPrefixes(releaseManifestService(true, DIGEST));

        MockHttpServletResponse kfeAdminResponse = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("POST", "/api/admin/kfe/audit/root"),
                kfeAdminResponse, new MockFilterChain());

        MockHttpServletResponse legacyAuditResponse = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("POST", "/v1/audit/siphon"),
                legacyAuditResponse, new MockFilterChain());

        assertEquals(403, kfeAdminResponse.getStatus());
        assertEquals(200, legacyAuditResponse.getStatus());
    }

    @Test
    void acceptsOutboundProofAndRejectsBodyTampering(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory) throws Exception {
        var manifest = directory.resolve("release.json");
        java.nio.file.Files.writeString(manifest, "{\"version\":\"test\"}");
        String digest = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(java.nio.file.Files.readAllBytes(manifest)));
        var outgoing = new org.springframework.mock.http.client.MockClientHttpRequest(
                org.springframework.http.HttpMethod.POST, java.net.URI.create("https://auth/internal/kfe/users"));
        byte[] body = "{\"message\":\"original\"}".getBytes(StandardCharsets.UTF_8);
        var signer = new com.kerosene.common.security.workload.ReleaseAttestationRequestInterceptor(
                manifest.toString(), SECRET, "spiffe://test/service/kfe");
        signer.intercept(outgoing, body, (request, bytes) ->
                new org.springframework.mock.http.client.MockClientHttpResponse(new byte[0], org.springframework.http.HttpStatus.OK));
        for (boolean tampered : new boolean[] {false, true}) {
            var incoming = new MockHttpServletRequest("POST", "/internal/kfe/users");
            outgoing.getHeaders().forEach((name, values) -> values.forEach(value -> incoming.addHeader(name, value)));
            incoming.setContent(tampered ? "changed".getBytes(StandardCharsets.UTF_8) : body);
            var response = new MockHttpServletResponse();
            filter(releaseManifestService(true, digest)).doFilter(incoming, response, new MockFilterChain());
            assertEquals(tampered ? 403 : 200, response.getStatus());
        }
    }

    private ReleaseAttestationFilter filter(ReleaseManifestService releaseManifestService) {
        return new ReleaseAttestationFilter(
                provider(releaseManifestService),
                true,
                false,
                300,
                SECRET,
                "",
                "/internal");
    }

    private ReleaseAttestationFilter filterWithDefaultPrefixes(ReleaseManifestService releaseManifestService) {
        return new ReleaseAttestationFilter(
                provider(releaseManifestService),
                true,
                false,
                300,
                SECRET,
                "",
                ReleaseAttestationFilter.DEFAULT_CRITICAL_PATH_PREFIXES);
    }

    private ReleaseManifestService releaseManifestService(boolean authorized, String manifestDigest) {
        ReleaseManifestService service = mock(ReleaseManifestService.class);
        when(service.isAuthorized()).thenReturn(authorized);
        when(service.manifestDigest()).thenReturn(manifestDigest);
        return service;
    }

    private ObjectProvider<ReleaseManifestService> provider(ReleaseManifestService service) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("releaseManifestService", service);
        return beanFactory.getBeanProvider(ReleaseManifestService.class);
    }

    private MockHttpServletRequest request(String digest)
            throws Exception {
        String body = "{\"operation\":\"settle\"}";
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String serviceIdentity = "kerosene-worker";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/settlement");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.addHeader(ReleaseAttestationFilter.RELEASE_DIGEST_HEADER, digest);
        request.addHeader(ReleaseAttestationFilter.RELEASE_TIMESTAMP_HEADER, timestamp);
        request.addHeader(ReleaseAttestationFilter.SERVICE_IDENTITY_HEADER, serviceIdentity);
        request.addHeader(ReleaseAttestationFilter.RELEASE_PROOF_HEADER,
                proof(request.getMethod(), request.getRequestURI(), serviceIdentity, digest, timestamp, body));
        return request;
    }

    private String proof(
            String method,
            String path,
            String serviceIdentity,
            String digest,
            String timestamp,
            String body)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String payload = method + "\n" + path + "\n" + serviceIdentity + "\n" + digest + "\n" + timestamp + "\n"
                + sha256Hex(body);
        return "hmac-sha256:" + Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }

    private String sha256Hex(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
