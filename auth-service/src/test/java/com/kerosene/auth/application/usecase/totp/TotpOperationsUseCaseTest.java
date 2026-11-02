package com.kerosene.auth.application.usecase.totp;

import org.junit.jupiter.api.Test;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationPort;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationRequest;
import com.kerosene.auth.application.service.identityaccess.TransactionalAuthenticationScope;
import org.mockito.ArgumentCaptor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import com.kerosene.auth.application.service.account.TotpManagementService;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.auth.dto.TotpSetupResponseDTO;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TotpOperationsUseCaseTest {

    private final TotpManagementService totpManagementService = mock(TotpManagementService.class);
    private final TransactionalAuthenticationPort authorization = mock(TransactionalAuthenticationPort.class);
    private final TotpOperationsUseCase useCase = new TotpOperationsUseCase(totpManagementService, authorization);

    @Test
    void setupDelegatesToTotpManagementService() {
        TotpSetupResponseDTO setupResponse = new TotpSetupResponseDTO("otpauth://totp/Kerosene:user", "secret");
        when(totpManagementService.beginSetup(42L)).thenReturn(setupResponse);

        TotpSetupResponseDTO result = useCase.setup(42L);

        assertSame(setupResponse, result);
        verify(totpManagementService).beginSetup(42L);
    }

    @Test
    void verifyDelegatesToTotpManagementService() {
        BackupCodesStatusDTO status = new BackupCodesStatusDTO(true, 10, List.of("12345678"));
        when(totpManagementService.verifySetup(42L, "123456")).thenReturn(status);

        BackupCodesStatusDTO result = useCase.verify(42L, "123456");

        assertSame(status, result);
        verify(totpManagementService).verifySetup(42L, "123456");
    }

    @Test
    void disableDelegatesToTotpManagementService() {
        useCase.disable(42L);

        var order = inOrder(authorization, totpManagementService);
        order.verify(authorization).authorize(any());
        order.verify(totpManagementService).disable(42L);
    }
    @Test
    void rejectedAuthorizationCannotDisableTotp() {
        doThrow(new AuthExceptions.InvalidCredentials("Rejected"))
                .when(authorization).authorize(any());
        assertThrows(AuthExceptions.InvalidCredentials.class,
                () -> useCase.disable(42L, "123456", "proof", " phrase "));
        verifyNoInteractions(totpManagementService);
    }

    @Test
    void disableBindsOwnerScopeAndPreservesFactors() {
        useCase.disable(42L, "123456", "proof", " phrase ");
        var request = ArgumentCaptor.forClass(TransactionalAuthenticationRequest.class);
        verify(authorization).authorize(request.capture());
        assertEquals(42L, request.getValue().authenticatedUserId());
        assertEquals(TransactionalAuthenticationScope.ACCOUNT_SECURITY_CHANGE, request.getValue().scope());
        assertEquals("123456", request.getValue().totpCode());
        assertEquals("proof", request.getValue().passkeyAssertionJson());
        assertEquals(" phrase ", request.getValue().confirmationPassphrase());
    }
}
