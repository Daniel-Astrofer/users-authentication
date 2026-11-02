package com.kerosene.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kerosene.auth.application.usecase.security.AppPinOperationsUseCase;
import com.kerosene.auth.application.usecase.security.RecoverAppPinUseCase;
import com.kerosene.auth.dto.AppPinStatusDTO;
import com.kerosene.auth.dto.RecoverAppPinRequestDTO;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Verifies the client recovery wire contract; the use-case tests exercise actual factor boundaries. */
class AppPinRecoveryHttpContractTest {
    @Test
    void acceptsPasswordAndNestedDeviceKeyProofAndReturnsTheExistingStatusEnvelope() throws Exception {
        var recovery = mock(RecoverAppPinUseCase.class);
        var status = new AppPinStatusDTO(true, true, false, 0, 5, 5, 4, 8, false, true, null, null, null);
        when(recovery.execute(eq("device-42"), any())).thenAnswer(invocation -> {
            RecoverAppPinRequestDTO request = invocation.getArgument(1);
            assertThat(request.getPassword()).containsExactly("account password".toCharArray());
            assertThat(request.getNewPin()).isEqualTo("0472");
            assertThat(request.getDeviceKey().getCredentialId()).isEqualTo("key-42");
            assertThat(request.getDeviceKey().getSignedPayload()).isEqualTo("canonical payload");
            assertThat(request.getDeviceKey().getSignature()).isEqualTo("signed proof");
            return status;
        });
        var mvc = MockMvcBuilders.standaloneSetup(new AppPinController(
                mock(AppPinOperationsUseCase.class), recovery)).build();
        mvc.perform(post("/auth/security/app-pin/recover").header("X-Device-Hash", "device-42")
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                {"password":"account password","newPin":"0472","deviceKey":{
                                 "username":"alice","credentialId":"key-42","deviceInstallId":"install-42",
                                 "signedPayload":"canonical payload","signature":"signed proof"}}
                                """))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.configured").value(true))
                .andExpect(jsonPath("$.data.enabled").value(true))
                .andExpect(jsonPath("$.data.password").doesNotExist())
                .andExpect(jsonPath("$.data.deviceKey").doesNotExist());
        verify(recovery).execute(eq("device-42"), any());
    }

    @Test
    void requestSecretsAreWriteOnlyWhenSerialized() throws Exception {
        var mapper = new ObjectMapper();
        var request = mapper.readValue("""
                {"password":"account password","newPin":"0472","deviceKey":{"signature":"signed proof"}}
                """, RecoverAppPinRequestDTO.class);
        String serialized = mapper.disable(com.fasterxml.jackson.databind.SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .writeValueAsString(request);
        assertThat(serialized).isEqualTo("{}");
    }
}
