package com.kerosene.platform.exception;

import com.kerosene.common.exception.ErrorCodes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.common.infra.logging.StructuredLogField;
import com.kerosene.platform.observability.FinancialOperationsMetrics;
import com.kerosene.common.exception.FinancialProviderUnavailableException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private FinancialOperationsMetrics financialMetrics;

    @BeforeEach
    void setUp() {
        MDC.clear();
        financialMetrics = mock(FinancialOperationsMetrics.class);
        handler = new GlobalExceptionHandler(financialMetrics);
    }

    @Test
    void shouldReturnStandardizedErrorCode_WhenUserAlreadyExists() {
        AuthExceptions.UserAlreadyExistsException ex = new AuthExceptions.UserAlreadyExistsException("test_user");
        ResponseEntity<ApiResponse<Void>> response = handler.handleUserAlreadyExists(ex);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals(ErrorCodes.AUTH_USER_ALREADY_EXISTS, response.getBody().getErrorCode());
        assertTrue(response.getBody().getMessage().contains("already exists"));
    }

    @Test
    void shouldSanitizeTechnicalMessage() {
        IllegalArgumentException ex = new IllegalArgumentException("Internal Error: NullPointerException at line 42 in DBDriver");
        ResponseEntity<ApiResponse<Void>> response = handler.handleIllegalArgument(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCodes.SYS_INVALID_ARGUMENTS, response.getBody().getErrorCode());
        assertEquals("The request contained invalid arguments.", response.getBody().getMessage());
        verify(financialMetrics).increment("validation_rejected", "rejected", "illegal_argument");
    }

    @Test
    void shouldBlockStacktraceKeywords() {
        String riskyMessage = "SqlException: table 'users' does not exist in database";
        String sanitized = invokeSanitize(riskyMessage, "Fallback");
        assertEquals("Fallback", sanitized);
    }

    @Test
    void shouldBlockJsonLeakage() {
        String riskyMessage = "{\"key\":\"sensitive\"}";
        String sanitized = invokeSanitize(riskyMessage, "Fallback");
        assertEquals("Fallback", sanitized);
    }

    @Test
    void shouldAllowBusinessMessage() {
        String businessMessage = "Your wallet is empty. Please deposit.";
        String sanitized = invokeSanitize(businessMessage, "Fallback");
        assertEquals(businessMessage, sanitized);
    }

    @Test
    void shouldReturnPaymentRequiredWhenInboundReceivingIsBlocked() {
        AuthExceptions.InboundReceivingBlockedException ex =
                new AuthExceptions.InboundReceivingBlockedException("Account cannot receive funds yet.");

        ResponseEntity<ApiResponse<Object>> response = handler.handleInboundReceivingBlocked(ex);

        assertEquals(HttpStatus.PAYMENT_REQUIRED, response.getStatusCode());
        assertEquals("ERR_ACCOUNT_DEPOSIT_REQUIRED", response.getBody().getErrorCode());
        assertEquals("Account cannot receive funds yet.", response.getBody().getMessage());
        assertEquals(
                "Ative uma carteira ou adicione saldo para receber pela plataforma.",
                ((Map<?, ?>) response.getBody().getData()).get("guidance"));
    }

    @Test
    void shouldReturnUnavailableWhenKfeProviderIsUnavailable() {
        FinancialProviderUnavailableException ex =
                new FinancialProviderUnavailableException("KFE rail provider is offline.");

        ResponseEntity<ApiResponse<Object>> response = handler.handleKfeProviderUnavailable(ex);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals("ERR_KFE_RAIL_PROVIDER_UNAVAILABLE", response.getBody().getErrorCode());
        assertEquals("The financial service is temporarily unavailable. Please try again later.",
                response.getBody().getMessage());
        assertEquals(
                "Os serviços de custódia e trilhos financeiros estão indisponíveis no momento. Tente novamente mais tarde.",
                ((Map<?, ?>) response.getBody().getData()).get("guidance"));
        verify(financialMetrics).increment("provider_unavailable", "unavailable", "kfe_rail");
    }

    @Test
    void shouldSanitizeTechnicalKeroseneExceptionMessage() {
        VaultException ex = new VaultException(
                "SQLException: select * from vault_keys",
                ErrorCodes.VAULT_STORAGE_ERROR);

        ResponseEntity<ApiResponse<Void>> response = handler.handleKeroseneException(ex);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(ErrorCodes.VAULT_STORAGE_ERROR, response.getBody().getErrorCode());
        assertEquals("The requested platform service is temporarily unavailable.", response.getBody().getMessage());
    }

    @Test
    void shouldPreserveKeroseneExceptionCode() {
        VaultException ex = new VaultException("Vault storage is temporarily unavailable.", ErrorCodes.VAULT_STORAGE_ERROR);

        ResponseEntity<ApiResponse<Void>> response = handler.handleKeroseneException(ex);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(ErrorCodes.VAULT_STORAGE_ERROR, response.getBody().getErrorCode());
        assertEquals("Vault storage is temporarily unavailable.", response.getBody().getMessage());
    }

    @Test
    void shouldIncludeTraceIdFromMdcInErrorBody() {
        MDC.put(StructuredLogField.TRACE_ID, "trace-backend-123");
        MDC.put(StructuredLogField.CORRELATION_ID, "corr-backend-456");

        ResponseEntity<ApiResponse<Void>> response = handler.handleIllegalArgument(new IllegalArgumentException("bad input"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("trace-backend-123", response.getBody().getTraceId());
    }

    @Test
    void shouldFallbackToCorrelationIdWhenTraceIdIsMissing() {
        MDC.put(StructuredLogField.CORRELATION_ID, "corr-backend-456");

        ResponseEntity<ApiResponse<Void>> response = handler.handleIllegalArgument(new IllegalArgumentException("bad input"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("corr-backend-456", response.getBody().getTraceId());
    }

    private String invokeSanitize(String raw, String fallback) {
        try {
            java.lang.reflect.Method method = GlobalExceptionHandler.class.getDeclaredMethod("sanitizeMessage", String.class, String.class);
            method.setAccessible(true);
            return (String) method.invoke(handler, raw, fallback);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
