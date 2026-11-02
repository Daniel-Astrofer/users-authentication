package com.kerosene.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.auth.application.usecase.activation.AccountActivationOperationsUseCase;
import com.kerosene.auth.dto.AccountActivationStatusDTO;
import com.kerosene.common.dto.ApiResponse;

import java.util.Map;

/**
 * Controller de status de ativação e do limite de recebimento de fundos de novos usuários.
 *
 * <p>Gerencia a verificação de status de ativação, geração de links de depósito
 * A criação de link e a confirmação externa descritas em clientes antigos estão desativadas nesta
 * implementação: o funding inicial deve ocorrer pelo fluxo interno da plataforma.</p>
 */
@RestController
@RequestMapping("/auth/activation-status")
public class AccountActivationController {

    private final AccountActivationOperationsUseCase accountActivationOperationsUseCase;

    /**
     * Creates the activation HTTP boundary.
     *
     * @param accountActivationOperationsUseCase application operations for the current user's status
     */
    public AccountActivationController(AccountActivationOperationsUseCase accountActivationOperationsUseCase) {
        this.accountActivationOperationsUseCase = accountActivationOperationsUseCase;
    }

    /**
     * Consulta o status atual de ativação da conta do usuário autenticado.
     *
     * <p><b>Endpoint:</b> {@code GET /auth/activation-status}<br>
     * <b>Autenticação:</b> Obrigatória (JWT de usuário)<br>
     * <b>Respostas:</b></p>
     * <ul>
     *   <li>{@code 200 OK} - Status retornado com sucesso contendo {@link AccountActivationStatusDTO}.</li>
     *   <li>{@code 401 UNAUTHORIZED} - Token ausente ou sessão expirada.</li>
     * </ul>
     *
     * @param authentication objeto de autenticação injetado pelo Spring Security
     * @return envelope {@link ApiResponse} contendo o DTO de status
     */
    @GetMapping
    public ResponseEntity<ApiResponse<AccountActivationStatusDTO>> getStatus(Authentication authentication) {
        AccountActivationStatusDTO status = accountActivationOperationsUseCase.getStatus(authenticatedUserId(authentication));
        return ResponseEntity.ok(ApiResponse.success("Activation status retrieved successfully.", status));
    }

    /**
     * Returns the current activation projection. The current use case does not create a funding link.
     *
     * <p><b>Endpoint:</b> {@code POST /auth/activation-status/funding-link}<br>
     * <b>Autenticação:</b> Obrigatória (JWT de usuário)<br>
     * <b>Respostas:</b></p>
     * <ul>
     *   <li>{@code 200 OK} - Current activation projection; funding-link fields remain unset.</li>
     *   <li>{@code 401 UNAUTHORIZED} - Usuário não autenticado.</li>
     * </ul>
     *
     * @param authentication credenciais do usuário autenticado
     * @return envelope with current activation status and no generated external link
     */
    @PostMapping("/funding-link")
    public ResponseEntity<ApiResponse<AccountActivationStatusDTO>> createFundingLink(Authentication authentication) {
        AccountActivationStatusDTO status =
                accountActivationOperationsUseCase.createOrReuseLink(authenticatedUserId(authentication));
        return ResponseEntity.ok(ApiResponse.success(
                "Initial funding is prepared inside the KFE flow.",
                status));
    }

    /**
     * Rejects the legacy external-link confirmation flow. Initial funding is handled inside the platform.
     *
     * <p><b>Endpoint:</b> {@code POST /auth/activation-status/{linkId}/confirm}<br>
     * <b>Autenticação:</b> Obrigatória (JWT de usuário)<br>
     * <b>Respostas:</b></p>
     * <ul>
     *   <li>{@code 400 BAD REQUEST} - External-link activation is disabled.</li>
     *   <li>{@code 401 UNAUTHORIZED} - Usuário não autenticado.</li>
     * </ul>
     *
     * @param linkId identificador do link de funding gerado previamente
     * @param request corpo contendo os campos {@code txid} e opcionalmente {@code fromAddress}
     * @param authentication credenciais do usuário autenticado
     * @return never returns normally; the application use case raises a validation error
     */
    @PostMapping("/{linkId}/confirm")
    public ResponseEntity<ApiResponse<AccountActivationStatusDTO>> confirm(
            @PathVariable String linkId,
            @RequestBody Map<String, String> request,
            Authentication authentication) {
        AccountActivationStatusDTO status = accountActivationOperationsUseCase.confirm(
                authenticatedUserId(authentication),
                linkId,
                request.get("txid"),
                request.get("fromAddress"));
        return ResponseEntity.ok(ApiResponse.success("Activation status retrieved successfully.", status));
    }

    /**
     * Converts the Spring Security principal name to the persisted user identifier.
     * Authentication is required by the surrounding security configuration.
     *
     * @param authentication principal supplied by Spring Security
     * @return numeric identifier used by account activation operations
     */
    private Long authenticatedUserId(Authentication authentication) {
        return Long.parseLong(authentication.getName());
    }
}
