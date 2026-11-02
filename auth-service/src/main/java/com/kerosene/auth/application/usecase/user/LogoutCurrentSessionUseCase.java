package com.kerosene.auth.application.usecase.user;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;

/** Revokes the bearer session identified by a logout request's Authorization header. */
@Component
public class LogoutCurrentSessionUseCase {

    /** Exact scheme prefix accepted before extracting the logout token. */
    private static final String BEARER_PREFIX = "Bearer ";

    /** JWT service that records revocation for the current token. */
    private final JwtServicer jwtService;

    /** Creates the logout operation with the session revocation boundary. */
    /** @param jwtService JWT validation and revocation service */
    public LogoutCurrentSessionUseCase(JwtServicer jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Extracts a bearer token and attempts to revoke it, returning a typed outcome for each case.
     * Runtime failures from revocation are represented as {@link Status#REVOCATION_FAILED}.
     *
     * @param authorization raw Authorization header value, possibly {@code null}
     * @return outcome indicating success, missing token, or failed revocation
     */
    public Result execute(String authorization) {
        String token = extractBearerToken(authorization);
        if (token == null) {
            return new Result(Status.MISSING_TOKEN);
        }

        try {
            jwtService.revokeSession(token);
            return new Result(Status.REVOKED);
        } catch (RuntimeException exception) {
            return new Result(Status.REVOCATION_FAILED);
        }
    }

    /** Returns the non-empty token portion of a correctly prefixed bearer header. */
    /** @param authorization raw Authorization header */
    /** @return trimmed token, or {@code null} when the scheme or token is missing */
    private String extractBearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = authorization.substring(BEARER_PREFIX.length()).trim();
        return token.isBlank() ? null : token;
    }

    /** Possible outcomes of the logout operation. */
    public enum Status {
        /** The bearer token was successfully submitted for revocation. */
        REVOKED,
        /** The request did not contain a non-empty bearer token. */
        MISSING_TOKEN,
        /** Revocation raised a runtime failure and could not be confirmed. */
        REVOCATION_FAILED
    }

    /**
     * Immutable result wrapper returned by the logout use case.
     *
     * @param status outcome selected by the use case
     */
    public record Result(Status status) {
    }
}
