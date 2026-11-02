package com.kerosene.security.infra;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Wraps the HttpServletRequest to allow its body to be read multiple times.
 *
 * <p>In Spring, {@link HttpServletRequest#getInputStream()} can only be consumed once.
 * This wrapper caches the body on first access so that both the
 * {@link HoneypotRequestFilter} and the downstream
 * {@link org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter}
 * can both read it without conflict.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    /** Immutable snapshot of the request body captured when this wrapper is created. */
    private final byte[] cachedBody;

    /** Reads and caches the underlying request body for repeatable downstream access.
     * @param request original servlet request
     * @throws IOException if reading the original body fails
     */
    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        InputStream requestInputStream = request.getInputStream();
        this.cachedBody = StreamUtils.copyToByteArray(requestInputStream);
    }

    /** Returns the original body bytes captured by this wrapper.
     * @return cached bytes, including an empty array for an empty body
     */
    public byte[] getCachedBody() {
        return cachedBody;
    }

    /** Returns a fresh stream over the cached body for each read attempt.
     * @return repeatable servlet input stream
     */
    @Override
    public ServletInputStream getInputStream() {
        return new CachedBodyServletInputStream(this.cachedBody);
    }

    /**
     * Lightweight {@link ServletInputStream} backed by a byte array.
     */
    private static class CachedBodyServletInputStream extends ServletInputStream {

        private final InputStream delegate;

        /** Creates an input stream backed by the supplied cached bytes.
         * @param body cached request bytes
         */
        public CachedBodyServletInputStream(byte[] body) {
            this.delegate = new ByteArrayInputStream(body);
        }

        @Override
        /** Reports whether all cached bytes have been consumed. */
        public boolean isFinished() {
            try {
                return delegate.available() == 0;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        /** Always reports ready because reads are served from memory. */
        public boolean isReady() {
            return true;
        }

        @Override
        /** Rejects asynchronous callbacks, which this memory-backed stream does not support.
         * @param readListener listener requested by the servlet container
         */
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException("Async not supported for cached body stream");
        }

        @Override
        /** Reads the next cached byte, or -1 when the body is exhausted.
         * @return next byte value or -1 at end of stream
         * @throws IOException if the backing stream reports a read error
         */
        public int read() throws IOException {
            return delegate.read();
        }
    }
}
