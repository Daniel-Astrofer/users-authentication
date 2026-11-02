package com.kerosene.platform.exception;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.RedisSystemException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.orchestrator.signup.FinalizeSignupAccount;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.common.infra.logging.StructuredLogField;
import com.kerosene.platform.observability.FinancialOperationsMetrics;
import com.kerosene.common.exception.FinancialSelfPaymentException;
import com.kerosene.common.exception.FinancialProviderUnavailableException;
import com.kerosene.common.exception.ErrorCodes;
import com.kerosene.common.exception.KeroseneException;
import com.kerosene.common.exception.StructuredPlatformException;

import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** Converts authentication, validation, platform, and infrastructure exceptions into safe API envelopes. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** Logger for sanitized request failures and infrastructure incidents. */
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    /** Generic fallback text used when request validation has no safe details. */
    private static final String INVALID_ARGUMENTS_MESSAGE = "The request contained invalid arguments.";
    /** Detects implementation details that must not be returned to API callers. */
    private static final Pattern TECHNICAL_MESSAGE_PATTERN = Pattern.compile(
            "(?i)(exception|stacktrace|sql|jdbc|hibernate|database|nullpointer|select\\s|insert\\s|update\\s|delete\\s|org\\.|java\\.|source\\.|\\bat\\s+[a-z0-9_$.]+\\(|\\{.*\\}|\\[.*\\])");

    /** Optional counter sink; absent in reduced or test application configurations. */
    private FinancialOperationsMetrics financialMetrics;

    /** Creates the advice without optional metrics. */
    public GlobalExceptionHandler() {
    }

    /** Creates the advice with a metrics sink.
     * @param financialMetrics financial outcome counter adapter
     */
    public GlobalExceptionHandler(FinancialOperationsMetrics financialMetrics) {
        this.financialMetrics = financialMetrics;
    }

    /** Injects metrics when the application context provides the optional adapter.
     * @param financialMetrics financial outcome counter adapter, or null when absent
     */
    @Autowired(required = false)
    public void setFinancialMetrics(FinancialOperationsMetrics financialMetrics) {
        this.financialMetrics = financialMetrics;
    }

    /** Maps duplicate-account failures to HTTP 409 and the stable auth conflict code.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserAlreadyExists(AuthExceptions.UserAlreadyExistsException ex) {
        return buildErrorResponse(
                HttpStatus.CONFLICT,
                "Failed to create account: A user with this username already exists. Please choose a different username.",
                ErrorCodes.AUTH_USER_ALREADY_EXISTS);
    }

    /** Maps missing usernames to the standard HTTP 400 validation envelope.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.UsernameCantBeNull.class)
    public ResponseEntity<ApiResponse<Void>> handleUsernameNull(AuthExceptions.UsernameCantBeNull ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Validation Error: The username field cannot be null or empty. Please provide a valid username.",
                ErrorCodes.AUTH_USERNAME_NULL);
    }

    /** Maps missing passphrases to the standard HTTP 400 validation envelope.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.PassphraseCantBeNull.class)
    public ResponseEntity<ApiResponse<Void>> handlePassphraseNull(AuthExceptions.PassphraseCantBeNull ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Validation Error: The password field cannot be null or empty. Please provide a strong password.",
                ErrorCodes.AUTH_PASSPHRASE_NULL);
    }

    /** Maps usernames containing unsupported characters to HTTP 400.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.InvalidCharacterUsername.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCharacter(AuthExceptions.InvalidCharacterUsername ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Validation Error: The username contains invalid characters. Please use only allowed alphanumeric characters.",
                ErrorCodes.AUTH_INVALID_USERNAME_CHAR);
    }

    /** Maps username or passphrase length failures to HTTP 400.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.CharacterLimitException.class)
    public ResponseEntity<ApiResponse<Void>> handleCharLimit(AuthExceptions.CharacterLimitException ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Validation Error: The username or password exceeds the allowed character limit. Please shorten your input.",
                ErrorCodes.AUTH_CHARACTER_LIMIT);
    }

    /** Maps account lookup failures to HTTP 404.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(AuthExceptions.UserNotFoundException ex) {
        return buildErrorResponse(
                HttpStatus.NOT_FOUND,
                "Authentication Failed: No account could be found matching the provided username. Verify the username and try again.",
                ErrorCodes.AUTH_USER_NOT_FOUND);
    }

    /** Maps passphrase-policy failures to HTTP 400.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.InvalidPassphrase.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidPassphrase(AuthExceptions.InvalidPassphrase ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Validation Error: The provided password is invalid or does not meet the required strength policy.",
                ErrorCodes.AUTH_INVALID_PASSPHRASE);
    }

    /** Maps invalid or expired authenticator codes to HTTP 401.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.IncorrectTotpException.class)
    public ResponseEntity<ApiResponse<Void>> handleIncorrectTotp(AuthExceptions.IncorrectTotpException ex) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Authentication Failed: The provided TOTP code is incorrect or expired. Please check your authenticator app and try again.",
                ErrorCodes.AUTH_INCORRECT_TOTP);
    }

    /** Maps credential verification failures to HTTP 401.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.InvalidCredentials.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(AuthExceptions.InvalidCredentials ex) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Authentication Failed: Invalid credentials provided. The username or password you entered is incorrect.",
                ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    /** Maps untrusted-device challenges to HTTP 403.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.UnrecognizedDeviceException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnrecognizedDevice(AuthExceptions.UnrecognizedDeviceException ex) {
        return buildErrorResponse(
                HttpStatus.FORBIDDEN,
                "Security Alert: Unrecognized device detected. For your protection, you must verify this new device using TOTP.",
                ErrorCodes.AUTH_UNRECOGNIZED_DEVICE);
    }

    /** Maps expired TOTP verification windows to HTTP 408.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.TotpTimeExceededException.class)
    public ResponseEntity<ApiResponse<Void>> handleTotpTimeout(AuthExceptions.TotpTimeExceededException ex) {
        return buildErrorResponse(
                HttpStatus.REQUEST_TIMEOUT,
                "Session Expired: The time limit for completing TOTP verification has been exceeded. Please restart the login or signup process.",
                ErrorCodes.AUTH_TOTP_TIMEOUT);
    }

    /** Preserves the status, code, message, and data of a structured authentication failure.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.StructuredAuthException.class)
    public ResponseEntity<ApiResponse<Object>> handleStructuredAuthException(AuthExceptions.StructuredAuthException ex) {
        return buildErrorResponse(ex.getStatus(), ex.getMessage(), ex.getErrorCode(), ex.getData());
    }

    /** Maps general authentication validation failures to HTTP 400.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.AuthValidationException.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericAuthException(AuthExceptions.AuthValidationException ex) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Authentication Error: " + ex.getMessage(),
                ErrorCodes.AUTH_GENERIC);
    }

    /** Returns HTTP 402 with user guidance when inbound receiving is blocked by account funding rules.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(AuthExceptions.InboundReceivingBlockedException.class)
    public ResponseEntity<ApiResponse<Object>> handleInboundReceivingBlocked(
            AuthExceptions.InboundReceivingBlockedException ex) {
        return buildErrorResponse(
                HttpStatus.PAYMENT_REQUIRED,
                ex.getMessage(),
                "ERR_ACCOUNT_DEPOSIT_REQUIRED",
                Map.of("guidance", "Ative uma carteira ou adicione saldo para receber pela plataforma."));
    }

    /** Returns HTTP 503 with safe guidance when account finalization cannot access the Vault master key.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(FinalizeSignupAccount.VaultNotReadyException.class)
    public ResponseEntity<ApiResponse<Object>> handleVaultNotReady(FinalizeSignupAccount.VaultNotReadyException ex) {
        log.warn("[GlobalExceptionHandler] Vault cryptographic service is not ready");
        return buildErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                "The security service is temporarily unavailable. Please try again later.",
                "ERR_VAULT_NOT_READY",
                Map.of("guidance", "O cofre master não pôde ser ativado para esta conta. Tente novamente em instantes."));
    }

    /** Records provider unavailability and returns a sanitized HTTP 503 response for the KFE rail.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(FinancialProviderUnavailableException.class)
    public ResponseEntity<ApiResponse<Object>> handleKfeProviderUnavailable(FinancialProviderUnavailableException ex) {
        incrementFinancialMetric("provider_unavailable", "unavailable", "kfe_rail");
        return buildErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                "The financial service is temporarily unavailable. Please try again later.",
                "ERR_KFE_RAIL_PROVIDER_UNAVAILABLE",
                Map.of("guidance", "Os serviços de custódia e trilhos financeiros estão indisponíveis no momento. Tente novamente mais tarde."));
    }


    /** Records a validation rejection and returns HTTP 400 for a self-payment attempt.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(FinancialSelfPaymentException.class)
    public ResponseEntity<ApiResponse<Object>> handleKfeSelfPayment(FinancialSelfPaymentException ex) {
        incrementFinancialMetric("validation_rejected", "rejected", "self_payment");
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                ex.getMessage(),
                ErrorCodes.LEDGER_PAYMENT_SELF_PAY,
                Map.of("guidance", "Use um link ou destino de outra conta para concluir esta transacao."));
    }


    /** Preserves the status, code, message, and data of a structured platform failure.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(StructuredPlatformException.class)
    public ResponseEntity<ApiResponse<Object>> handleStructuredPlatformException(StructuredPlatformException ex) {
        return buildErrorResponse(ex.getStatus(), ex.getMessage(), ex.getErrorCode(), ex.getData());
    }

    /** Maps a platform service exception to HTTP 503 with sanitized client-facing text.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(KeroseneException.class)
    public ResponseEntity<ApiResponse<Void>> handleKeroseneException(KeroseneException ex) {
        return buildErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                sanitizeMessage(ex.getMessage(), "The requested platform service is temporarily unavailable."),
                ex.getErrorCode());
    }

    /** Records a state rejection and returns HTTP 409 for operations invalid in the current state.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalState(IllegalStateException ex) {
        incrementFinancialMetric("validation_rejected", "rejected", "illegal_state");
        return buildErrorResponse(
                HttpStatus.CONFLICT,
                sanitizeMessage(ex.getMessage(), "The requested operation cannot be completed in the current state."),
                "ERR_OPERATION_STATE");
    }

    /** Maps invalid input to HTTP 400, except the legacy missing-user signal, which becomes HTTP 401.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException ex) {
        if ("invalid user".equals(ex.getMessage())) {
            return buildErrorResponse(
                    HttpStatus.UNAUTHORIZED,
                    "Authentication Failed: The user associated with this session no longer exists. Please log in again.",
                    ErrorCodes.AUTH_INVALID_CREDENTIALS);
        }
        incrementFinancialMetric("validation_rejected", "rejected", "illegal_argument");
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                sanitizeMessage(ex.getMessage(), INVALID_ARGUMENTS_MESSAGE),
                ErrorCodes.SYS_INVALID_ARGUMENTS);
    }

    /** Collects distinct field validation messages and returns a sanitized HTTP 400 response.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(MethodArgumentNotValidException ex) {
        incrementFinancialMetric("validation_rejected", "rejected", "bean_validation");
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .distinct()
                .collect(Collectors.joining("; "));
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                sanitizeMessage(message, INVALID_ARGUMENTS_MESSAGE),
                ErrorCodes.SYS_INVALID_ARGUMENTS);
    }

    /** Records a constraint rejection and returns a generic HTTP 400 validation envelope.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleConstraintViolation(ConstraintViolationException ex) {
        incrementFinancialMetric("validation_rejected", "rejected", "constraint_violation");
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                INVALID_ARGUMENTS_MESSAGE,
                ErrorCodes.SYS_INVALID_ARGUMENTS);
    }

    /** Logs datastore failures and returns a generic HTTP 503 without exposing storage internals.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler({
            RedisSystemException.class,
            RedisConnectionFailureException.class,
            DataAccessException.class
    })
    public ResponseEntity<ApiResponse<Void>> handleDataAccess(DataAccessException ex) {
        log.error("[GlobalExceptionHandler] Data store unavailable: {} - {}",
                ex.getClass().getSimpleName(), ex.getMessage(), ex);
        return buildErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Service temporarily unavailable. Please try again in a moment.",
                ErrorCodes.SYS_INTERNAL_ERROR);
    }

    /** Logs unexpected failures and returns a generic HTTP 500 response.
     * @param ex exception handled by this mapping
     * @return HTTP error response using the shared API envelope
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleAllOtherExceptions(Exception ex) {
        log.error("[GlobalExceptionHandler] Unhandled exception: {} - {}", ex.getClass().getName(), ex.getMessage(), ex);
        return buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error: An unexpected error occurred on our end. Our team has been notified.",
                ErrorCodes.SYS_INTERNAL_ERROR);
    }

    /** Builds a failed API envelope with no detail payload.
     * @param status HTTP status for the mapped failure
     * @param message client-facing message
     * @param errorCode stable error identifier
     * @return response with trace/correlation identifier when available
     */
    private ResponseEntity<ApiResponse<Void>> buildErrorResponse(HttpStatus status, String message, String errorCode) {
        return ResponseEntity.status(status).body(ApiResponse.error(message, errorCode, null, currentTraceId()));
    }

    /** Builds a failed API envelope carrying structured client-safe details.
     * @param status HTTP status for the mapped failure
     * @param message client-facing message
     * @param errorCode stable error identifier
     * @param data structured details to include in the response
     * @param <T> detail payload type
     * @return response with trace/correlation identifier when available
     */
    private <T> ResponseEntity<ApiResponse<T>> buildErrorResponse(
            HttpStatus status,
            String message,
            String errorCode,
            T data) {
        return ResponseEntity.status(status).body(ApiResponse.error(message, errorCode, data, currentTraceId()));
    }

    /** Selects the current trace ID, falling back to the request correlation ID.
     * @return nonblank trace/correlation identifier, or null when neither exists
     */
    private String currentTraceId() {
        String traceId = safeMdcValue(MDC.get(StructuredLogField.TRACE_ID));
        if (traceId != null) {
            return traceId;
        }
        return safeMdcValue(MDC.get(StructuredLogField.CORRELATION_ID));
    }

    /** Trims an MDC value and treats null or blank text as absent.
     * @param value raw mapped diagnostic context value
     * @return trimmed value or null
     */
    private String safeMdcValue(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** Best-effort metric recording that does not interfere with error response generation.
     * @param name financial metric suffix
     * @param outcome operation result label
     * @param type operation category
     */
    private void incrementFinancialMetric(String name, String outcome, String type) {
        if (financialMetrics == null) {
            return;
        }
        try {
            financialMetrics.increment(name, outcome, type);
        } catch (RuntimeException exception) {
            log.warn("[GlobalExceptionHandler] Failed to increment financial metric {}: {}", name, exception.getMessage());
        }
    }

    /** Rejects messages that are blank, oversized, or contain likely implementation details.
     * @param rawMessage candidate exception text
     * @param fallbackMessage safe text used when the candidate is unsuitable
     * @return sanitized candidate or fallback text
     */
    private String sanitizeMessage(String rawMessage, String fallbackMessage) {
        if (rawMessage == null) {
            return fallbackMessage;
        }
        String normalized = rawMessage.trim();
        if (normalized.isEmpty() || normalized.length() > 180) {
            return fallbackMessage;
        }
        if (TECHNICAL_MESSAGE_PATTERN.matcher(normalized).find()) {
            return fallbackMessage;
        }
        return normalized;
    }
}
