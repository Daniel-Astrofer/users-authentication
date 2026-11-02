package com.kerosene.auth.application.service.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.kerosene.auth.application.infra.persistence.jpa.AdminAccessAttemptRepository;
import com.kerosene.auth.application.infra.persistence.jpa.AdminAccessDeviceRepository;
import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.dto.AdminLoginResponseDTO;
import com.kerosene.auth.model.entity.AdminAccessAttemptEntity;
import com.kerosene.auth.model.entity.AdminAccessDeviceEntity;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.auth.model.enums.AdminAccessAttemptStatus;
import com.kerosene.auth.model.enums.AdminAccessDeviceStatus;
import com.kerosene.auth.model.enums.UserRole;
import com.kerosene.common.infra.logging.LogSanitizer;

class AdminAccessServiceTest {

    private final JwtServicer jwtServicer = mock(JwtServicer.class);
    private final AdminAccessDeviceRepository deviceRepository = mock(AdminAccessDeviceRepository.class);
    private final AdminAccessAttemptRepository attemptRepository = mock(AdminAccessAttemptRepository.class);
    private final AdminAccessService service = new AdminAccessService(
            null,
            jwtServicer,
            null,
            null,
            deviceRepository,
            attemptRepository,
            null,
            null);

    @Test
    void pollLoginConsumesApprovedAttemptWhenReturningToken() {
        UUID attemptId = UUID.randomUUID();
        AdminAccessAttemptEntity attempt = approvedAttempt();
        when(attemptRepository.findForPollingById(attemptId)).thenReturn(Optional.of(attempt));
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, List.of(UserRole.ADMIN.name()), 0L)).thenReturn("jwt-token");

        AdminLoginResponseDTO response = service.pollLogin(attemptId, "203.0.113.10", "Desktop Browser");

        assertEquals("APPROVED", response.status());
        assertFalse(response.requiresMobileApproval());
        assertEquals("42 jwt-token", response.token());
        assertEquals(AdminAccessAttemptStatus.REDEEMED, attempt.getStatus());
        verify(attemptRepository).save(attempt);
    }

    @Test
    void pollLoginDoesNotReturnTokenAfterAttemptWasConsumed() {
        UUID attemptId = UUID.randomUUID();
        AdminAccessAttemptEntity attempt = approvedAttempt();
        when(attemptRepository.findForPollingById(attemptId)).thenReturn(Optional.of(attempt));
        when(jwtServicer.generateTokenAtCredentialEpoch(42L, List.of(UserRole.ADMIN.name()), 0L)).thenReturn("jwt-token");

        service.pollLogin(attemptId, "203.0.113.10", "Desktop Browser");
        AdminLoginResponseDTO secondResponse = service.pollLogin(attemptId, "203.0.113.10", "Desktop Browser");

        assertNull(secondResponse.token());
        assertFalse(secondResponse.requiresMobileApproval());
        assertTrue(secondResponse.message().contains("ja foi utilizada"));
        verify(jwtServicer).generateTokenAtCredentialEpoch(42L, List.of(UserRole.ADMIN.name()), 0L);
    }

    @Test
    void pollLoginDoesNotGenerateTokenForAlreadyConsumedAttempt() {
        UUID attemptId = UUID.randomUUID();
        AdminAccessAttemptEntity attempt = approvedAttempt();
        attempt.setStatus(AdminAccessAttemptStatus.REDEEMED);
        when(attemptRepository.findForPollingById(attemptId)).thenReturn(Optional.of(attempt));

        AdminLoginResponseDTO response = service.pollLogin(attemptId, "203.0.113.10", "Desktop Browser");

        assertEquals("REDEEMED", response.status());
        assertNull(response.token());
        assertFalse(response.requiresMobileApproval());
        verify(jwtServicer, never()).generateTokenAtCredentialEpoch(anyLong(), anyCollection(), anyLong());
    }

    private AdminAccessAttemptEntity approvedAttempt() {
        UserDataBase user = mock(UserDataBase.class);
        when(user.getId()).thenReturn(42L);

        AdminAccessDeviceEntity device = new AdminAccessDeviceEntity();
        device.setStatus(AdminAccessDeviceStatus.PENDING);

        AdminAccessAttemptEntity attempt = new AdminAccessAttemptEntity();
        attempt.setUser(user);
        attempt.setDevice(device);
        attempt.setStatus(AdminAccessAttemptStatus.APPROVED);
        attempt.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        attempt.setIpFingerprint(LogSanitizer.fingerprint("203.0.113.10"));
        attempt.setUserAgent("Desktop Browser");
        return attempt;
    }
}
