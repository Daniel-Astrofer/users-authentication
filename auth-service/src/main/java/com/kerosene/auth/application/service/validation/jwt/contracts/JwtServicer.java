package com.kerosene.auth.application.service.validation.jwt.contracts;

import java.util.Collection;
import java.util.List;

/** Authentication boundary for token issuance, claim extraction, and session revocation. */
public interface JwtServicer {
    /**
     * Issues a token for an authenticated principal with the default USER authority.
     *
     * @param id principal identifier embedded in the token
     * @return signed token string
     */
    String generateToken(long id);

    /**
     * Issues a token with explicit authorities.
     *
     * @param id principal identifier embedded in the token
     * @param roles authorities to encode as claims
     * @return signed token string
     */
    String generateToken(long id, Collection<String> roles);

    /** Binds a session to the credential generation whose proof was actually verified. */
    String generateTokenAtCredentialEpoch(long id, Collection<String> roles, long credentialEpoch);

    /**
     * Issues a token associated with a revocable session when the implementation supports session claims.
     * The default implementation preserves compatibility by delegating to the role-aware overload and ignoring sessionId.
     *
     * @param id principal identifier embedded in the token
     * @param roles authorities to encode as claims
     * @param sessionId optional session revocation identifier
     * @return signed token string
     */
    default String generateToken(long id, Collection<String> roles, String sessionId) {
        return generateToken(id, roles);
    }

    /**
     * Extracts the authenticated principal identifier from a signed token.
     *
     * @param token signed token to inspect
     * @return principal identifier encoded by the implementation
     */
    Long extractId(String token);

    /**
     * Extracts an optional revocable session identifier.
     * The compatibility default returns null when the implementation has no session claim support.
     *
     * @param token signed token to inspect
     * @return session identifier, or null when absent or unsupported
     */
    default String extractSessionId(String token) {
        return null;
    }

    /**
     * Checks whether the token's session was revoked.
     * The compatibility default reports false when revocation storage is not implemented.
     *
     * @param token signed token to inspect
     * @return true when the associated session is revoked
     */
    default boolean isSessionRevoked(String token) {
        return false;
    }

    /**
     * Revokes the session associated with the token until its expiry.
     * The compatibility default is a no-op for implementations without session revocation.
     *
     * @param token signed token whose session should be revoked
     */
    default void revokeSession(String token) {
    }

    /**
     * Extracts authorities encoded in a token.
     * The compatibility default assigns USER when role claims are unsupported.
     *
     * @param token signed token to inspect
     * @return token authorities in implementation-defined order
     */
    default List<String> extractRoles(String token) {
        return List.of("USER");
    }
}
