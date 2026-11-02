package com.kerosene.auth.application.usecase.activation;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.account.AccountActivationService;
import com.kerosene.auth.dto.AccountActivationStatusDTO;

/** Exposes account-activation status, link creation, and confirmation as application operations. */
@Component
public class AccountActivationOperationsUseCase {

    /** Domain service implementing activation-link lifecycle and confirmation rules. */
    private final AccountActivationService accountActivationService;

    /**
     * Creates the activation operations facade.
     *
     * @param accountActivationService service implementing activation status and inbound eligibility
     */
    public AccountActivationOperationsUseCase(AccountActivationService accountActivationService) {
        this.accountActivationService = accountActivationService;
    }

    /**
     * Retrieves current activation progress for an account.
     *
     * @param userId persisted account identifier
     * @return activation status projection used by the API boundary
     */
    public AccountActivationStatusDTO getStatus(Long userId) {
        return accountActivationService.getStatus(userId);
    }

    /**
     * Delegates link creation or reuse to the activation service; the current implementation returns
     * account activation state without creating an external payment link.
     *
     * @param userId persisted account identifier
     * @return current activation status and any link metadata supplied by the service
     */
    public AccountActivationStatusDTO createOrReuseLink(Long userId) {
        return accountActivationService.createOrReuseLink(userId);
    }

    /**
     * Delegates a legacy activation confirmation to the service, which currently rejects this flow.
     * Initial deposits are expected to use the in-platform funding flow.
     *
     * @param userId persisted account identifier
     * @param linkId legacy activation link identifier
     * @param txid legacy transaction identifier supplied as evidence
     * @param fromAddress legacy source address supplied as evidence
     * @return updated activation status if a future supported flow returns normally
     */
    public AccountActivationStatusDTO confirm(Long userId, String linkId, String txid, String fromAddress) {
        return accountActivationService.confirm(userId, linkId, txid, fromAddress);
    }
}
