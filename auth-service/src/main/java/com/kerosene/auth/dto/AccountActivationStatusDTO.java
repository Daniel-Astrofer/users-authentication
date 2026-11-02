package com.kerosene.auth.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * API projection of account activation and the current inbound-funding gate.
 *
 * @param activated whether the account has completed activation
 * @param canReceiveInbound whether inbound platform funds are currently permitted
 * @param requiresActivationDeposit whether activation is still pending
 * @param requiredAmountBtc amount currently reported as required for activation
 * @param paymentLinkId activation payment link, when one has been created
 * @param depositAddress address for the activation deposit, when one is available
 * @param paymentStatus external payment state, when supplied by the activation flow
 * @param warningMessage user-facing explanation for an inactive account
 * @param activatedAt activation timestamp, or null before activation
 */
public record AccountActivationStatusDTO(
        boolean activated,
        boolean canReceiveInbound,
        boolean requiresActivationDeposit,
        BigDecimal requiredAmountBtc,
        String paymentLinkId,
        String depositAddress,
        String paymentStatus,
        String warningMessage,
        LocalDateTime activatedAt) {

    /**
     * Stable user-facing message explaining why inbound platform funds are blocked.
     */
    public static final String INBOUND_BLOCKED_MESSAGE =
            "Para receber fundos dentro da plataforma, deposite algum valor primeiro.";

    /**
     * Maps the active flag and activation timestamp into the API response; payment fields remain unset.
     * @param user minimal account view required for activation projection
     * @return activation status derived from the user's active state
     */
    public static AccountActivationStatusDTO from(UserDataBaseView user) {
        return new AccountActivationStatusDTO(
                user.isActive(),
                user.isActive(),
                !user.isActive(),
                BigDecimal.ZERO,
                null,
                null,
                null,
                user.isActive()
                        ? null
                        : INBOUND_BLOCKED_MESSAGE,
                user.activatedAt());
    }

    /**
     * Minimal persistence projection used to avoid loading a complete account entity.
     */
    public interface UserDataBaseView {
        /**
         * Reports whether activation is complete.
         *
         * @return current active state
         */
        boolean isActive();

        /**
         * Returns the activation time.
         *
         * @return timestamp or null when inactive
         */
        LocalDateTime activatedAt();
    }
}
