package com.kerosene.auth;

import org.springframework.http.HttpStatus;

/**
 * Centralized exception classes for authentication and authorization
 * operations.
 * All exceptions extend AuthValidationException for consistent error handling.
 */
public class AuthExceptions {

    /** Creates the exception namespace; application code normally instantiates a nested exception type. */
    public AuthExceptions() {
    }

    /**
     * Base exception for all authentication validation errors.
     */
    public static class AuthValidationException extends RuntimeException {
        /**
         * Creates a validation exception with its client-safe message.
         * @param message diagnostic message consumed by centralized exception handling
         */
        public AuthValidationException(String message) {
            super(message);
        }
    }

    /** Authentication exception carrying an HTTP status, stable error code, and optional response data. */
    public static class StructuredAuthException extends AuthValidationException {
        /** HTTP status selected by the use case. */
        private final HttpStatus status;
        /** Stable machine-readable authentication error code. */
        private final String errorCode;
        /** Optional structured response details. */
        private final Object data;

        /**
         * Creates an error response with explicit transport and payload metadata.
         * @param message client-facing error message
         * @param status HTTP status returned by the exception handler
         * @param errorCode stable error code for clients
         * @param data optional structured response data
         */
        public StructuredAuthException(String message, HttpStatus status, String errorCode, Object data) {
            super(message);
            this.status = status;
            this.errorCode = errorCode;
            this.data = data;
        }

        /**
         * Returns the transport status selected by the application operation.
         *
         * @return HTTP status carried by this exception
         */
        public HttpStatus getStatus() {
            return status;
        }

        /**
         * Returns the stable code clients may use to branch on this failure.
         *
         * @return machine-readable error code
         */
        public String getErrorCode() {
            return errorCode;
        }

        /**
         * Returns optional structured details included by the centralized exception handler.
         *
         * @return response data, or null when the error has no additional payload
         */
        public Object getData() {
            return data;
        }
    }

    /**
     * Thrown when an account can use the platform but cannot receive funds yet.
     */
    public static class InboundReceivingBlockedException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message explanation that the account cannot currently receive funds
         */
        public InboundReceivingBlockedException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when user fails to register a Passkey which is mandatory.
     */
    public static class MissingPasskey extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message explanation that required passkey registration is missing
         */
        public MissingPasskey(String message) {
            super(message);
        }
    }

    /**
     * Thrown when attempting to create a user that already exists.
     */
    public static class UserAlreadyExistsException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message duplicate-account explanation
         */
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when username is null or blank.
     */
    public static class UsernameCantBeNull extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message username validation detail
         */
        public UsernameCantBeNull(String message) {
            super(message);
        }
    }

    /**
     * Thrown when passphrase is null.
     */
    public static class PassphraseCantBeNull extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message passphrase validation detail
         */
        public PassphraseCantBeNull(String message) {
            super(message);
        }
    }

    /**
     * Thrown when username contains invalid characters.
     */
    public static class InvalidCharacterUsername extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message username character validation detail
         */
        public InvalidCharacterUsername(String message) {
            super(message);
        }
    }

    /**
     * Thrown when username or passphrase exceeds character limit.
     */
    public static class CharacterLimitException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message maximum-length validation detail
         */
        public CharacterLimitException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when user does not exist in the database.
     */
    public static class UserNotFoundException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message user lookup failure detail
         */
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when passphrase is invalid or doesn't meet BIP39 requirements.
     */
    public static class InvalidPassphrase extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message passphrase or BIP39 validation detail
         */
        public InvalidPassphrase(String message) {
            super(message);
        }
    }

    /**
     * Thrown when TOTP code is incorrect.
     */
    public static class IncorrectTotpException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message TOTP mismatch detail
         */
        public IncorrectTotpException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when login credentials are invalid.
     */
    public static class InvalidCredentials extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message generic credential rejection detail
         */
        public InvalidCredentials(String message) {
            super(message);
        }
    }

    /**
     * Thrown when device is not recognized.
     */
    public static class UnrecognizedDeviceException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message device recognition failure detail
         */
        public UnrecognizedDeviceException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when TOTP verification time window has exceeded.
     */
    public static class TotpTimeExceededException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message expired TOTP verification window detail
         */
        public TotpTimeExceededException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when an emergency recovery request is rejected without disclosing
     * whether the username or recovery codes were valid.
     */
    public static class RecoveryRejectedException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message non-enumerating emergency recovery rejection detail
         */
        public RecoveryRejectedException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when the emergency recovery flow is being rate limited or blocked.
     */
    public static class RecoveryRateLimitedException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message recovery throttling or denial detail
         */
        public RecoveryRateLimitedException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when the emergency recovery session expired or was already consumed.
     */
    public static class RecoverySessionExpiredException extends AuthValidationException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message recovery session expiry or replay detail
         */
        public RecoverySessionExpiredException(String message) {
            super(message);
        }
    }

    // Deprecated exceptions - mantidos para compatibilidade, serão removidos em
    // versão futura
    /**
     * @deprecated Use {@link CharacterLimitException} instead
     */
    @Deprecated
    public static class UsernameCharacterLimitException extends CharacterLimitException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message legacy username length validation detail
         */
        public UsernameCharacterLimitException(String message) {
            super(message);
        }
    }

    /**
     * @deprecated Use {@link UserNotFoundException} instead
     */
    @Deprecated
    public static class UserNoExists extends UserNotFoundException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message legacy user lookup failure detail
         */
        public UserNoExists(String message) {
            super(message);
        }
    }

    /**
     * @deprecated Use {@link IncorrectTotpException} instead
     */
    @Deprecated
    public static class incorrectTotp extends IncorrectTotpException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message legacy TOTP mismatch detail
         */
        public incorrectTotp(String message) {
            super(message);
        }
    }

    /**
     * @deprecated Use {@link UnrecognizedDeviceException} instead
     */
    @Deprecated
    public static class UnrrecognizedDevice extends UnrecognizedDeviceException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message legacy device recognition failure detail
         */
        public UnrrecognizedDevice(String message) {
            super(message);
        }
    }

    /**
     * @deprecated Use {@link TotpTimeExceededException} instead
     */
    @Deprecated
    public static class TotpTimeExceded extends TotpTimeExceededException {
        /**
         * Creates this exception with the supplied operation-specific validation message.
         *
         * @param message legacy expired TOTP window detail
         */
        public TotpTimeExceded(String message) {
            super(message);
        }
    }
}
