package com.kerosene.auth.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import com.kerosene.auth.application.usecase.totp.TotpOperationsUseCase;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.auth.dto.TotpSetupResponseDTO;
import com.kerosene.common.dto.ApiResponse;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TotpControllerTest {

    private final TotpOperationsUseCase totpOperationsUseCase = mock(TotpOperationsUseCase.class);
    private final TotpController controller = new TotpController(totpOperationsUseCase);

    @Test
    void setupDelegatesParsedUserIdAndMapsSuccessMessage() {
        Authentication authentication = authentication("42");
        TotpSetupResponseDTO setupResponse = new TotpSetupResponseDTO("otpauth://totp/Kerosene:user", "secret");
        when(totpOperationsUseCase.setup(42L)).thenReturn(setupResponse);

        ResponseEntity<ApiResponse<TotpSetupResponseDTO>> response = controller.setup(authentication);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("TOTP setup secret generated successfully.", response.getBody().getMessage());
        assertEquals(setupResponse, response.getBody().getData());
        verify(totpOperationsUseCase).setup(42L);
    }

    @Test
    void verifyDelegatesParsedUserIdAndMapsSuccessMessage() {
        Authentication authentication = authentication("42");
        BackupCodesStatusDTO status = new BackupCodesStatusDTO(true, 10, List.of("12345678"));
        when(totpOperationsUseCase.verify(42L, "123456")).thenReturn(status);

        ResponseEntity<ApiResponse<BackupCodesStatusDTO>> response = controller.verify(
                authentication,
                Map.of("totpCode", "123456"));

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("TOTP enabled successfully.", response.getBody().getMessage());
        assertEquals(status, response.getBody().getData());
        verify(totpOperationsUseCase).verify(42L, "123456");
    }

    @Test
    void disableDelegatesParsedUserIdAndMapsSuccessMessageAndData() {
        Authentication authentication = authentication("42");

        ResponseEntity<ApiResponse<String>> response = controller.disable(authentication);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("TOTP disabled successfully.", response.getBody().getMessage());
        assertEquals("OK", response.getBody().getData());
        verify(totpOperationsUseCase).disable(42L, null, null, null);
    }

    @Test
    void disableForwardsFactorsWithoutChangingThePrincipal() {
        controller.disable(authentication("42"),
                new TotpController.DisableTotpRequest("123456", "proof", " phrase "));
        verify(totpOperationsUseCase).disable(42L, "123456", "proof", " phrase ");
    }

    private Authentication authentication(String name) {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(name);
        return authentication;
    }
}
