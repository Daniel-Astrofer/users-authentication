package com.kerosene.auth.application.usecase.security;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.account.AccountSecurityStatusService;
import com.kerosene.auth.dto.AccountSecurityStatusDTO;

/** Retrieves the summarized security status for an account. */
@Component
public class GetAccountSecurityStatusUseCase {

    /** Domain service that assembles security readiness and status. */
    private final AccountSecurityStatusService accountSecurityStatusService;

    /**
     * Creates the account security status query.
     *
     * @param accountSecurityStatusService service assembling the account's readiness projection
     */
    public GetAccountSecurityStatusUseCase(AccountSecurityStatusService accountSecurityStatusService) {
        this.accountSecurityStatusService = accountSecurityStatusService;
    }

    /**
     * Delegates account status lookup to the security status service.
     *
     * @param userId persisted account identifier
     * @return security status projection
     */
    public AccountSecurityStatusDTO execute(Long userId) {
        return accountSecurityStatusService.getStatus(userId);
    }
}
