package com.kerosene.notification.integration;

import org.springframework.context.annotation.Primary;
import org.springframework.beans.factory.annotation.Autowired;
import com.kerosene.common.financial.notification.FinancialNotificationEventRequest;
import com.kerosene.common.financial.notification.FinancialNotificationReceipt;
import com.kerosene.notification.service.FinancialNotificationEventService;
import com.kerosene.notification.service.FinancialNotificationPayloads;
import java.time.Instant;
import org.springframework.stereotype.Component;
import com.kerosene.common.financial.notification.FinancialNotificationPort;
import com.kerosene.notification.l10n.NotificationMessageKey;
import com.kerosene.notification.l10n.NotificationMessages;
import com.kerosene.notification.model.NotificationKind;
import com.kerosene.notification.model.NotificationSeverity;
import com.kerosene.notification.service.NotificationService;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
@Primary
public class NotificationFinancialNotificationAdapter implements FinancialNotificationPort {

    private final NotificationService notificationService;

    private final FinancialNotificationEventService events;

    @Autowired
    public NotificationFinancialNotificationAdapter(NotificationService notificationService,
                                                     FinancialNotificationEventService events) {
        this.notificationService = notificationService;
        this.events = events;
    }

    public NotificationFinancialNotificationAdapter(NotificationService notificationService) {
        this(notificationService, null);
    }

    @Override
    public FinancialNotificationReceipt deliverEvent(FinancialNotificationEventRequest event) {
        if (events == null) throw new IllegalStateException("Financial inbox is not configured.");
        return events.accept(event);
    }

    private void lifecycle(FinancialNotificationEventRequest.Type type, Long userId, UUID tx,
                           UUID wallet, String rail, long amount, int confirmations, String reference,
                           String failureCode) {
        notificationService.notifyUser(userId, FinancialNotificationPayloads.from(
                new FinancialNotificationEventRequest(UUID.randomUUID(), 1, type, userId,
                        tx, wallet, rail, amount, confirmations, reference, failureCode, null, null, Instant.now())));
    }

    @Override
    public void notifyPaymentInitiated(Long userId, UUID tx, UUID wallet, String rail, long amount) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_PROCESSING, userId, tx, wallet, rail, amount, 0, null, null);
    }

    @Override
    public void notifyPaymentBroadcast(Long userId, UUID tx, UUID wallet, String rail, long amount, String reference) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_BROADCAST, userId, tx, wallet, rail, amount, 0, reference, null);
    }

    @Override
    public void notifyPaymentConfirmed(Long userId, UUID tx, UUID wallet, String rail, long amount, int confirmations) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_CONFIRMED, userId, tx, wallet, rail, amount, confirmations, null, null);
    }

    @Override
    public void notifyPaymentFailed(Long userId, UUID tx, UUID wallet, String rail, long amount, String code, String ignoredProviderMessage) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_FAILED, userId, tx, wallet, rail, amount, 0, null, code);
    }

    @Override
    public void notifyPaymentReconciliationRequired(Long userId, UUID tx, UUID wallet, String rail, long amount, String ignoredProviderMessage) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_RECONCILIATION_REQUIRED, userId, tx, wallet, rail, amount, 0, null, null);
    }

    @Override
    public void notifyOutboundConflicted(Long userId, UUID tx, UUID wallet, String rail, long amount, String reference) {
        lifecycle(FinancialNotificationEventRequest.Type.PAYMENT_CONFLICTED, userId, tx, wallet, rail, amount, 0, reference, null);
    }

    @Override
    public void notifyDepositConfirmed(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long creditedSats,
            int confirmations) {
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.DEPOSIT_CONFIRMED,
                        NotificationSeverity.SUCCESS,
                        depositMessageKey(rail),
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        creditMeta(transactionId, walletId, rail, creditedSats, confirmations, "INBOUND"),
                        satsToBtc(creditedSats)));
    }

    @Override
    public void notifyPaymentRequestDepositConfirmed(
            Long userId,
            UUID transactionId,
            UUID paymentRequestId,
            String publicId,
            UUID walletId,
            String rail,
            long creditedSats) {
        Map<String, String> meta = creditMeta(transactionId, walletId, rail, creditedSats, null, "INBOUND");
        meta.put("paymentRequestId", paymentRequestId.toString());
        if (publicId != null) {
            meta.put("publicId", publicId);
        }
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.DEPOSIT_CONFIRMED,
                        NotificationSeverity.SUCCESS,
                        depositMessageKey(rail),
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        meta,
                        satsToBtc(creditedSats)));
    }

    @Override
    public void notifyDepositDetected(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long creditedSats,
            int confirmations) {
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.DEPOSIT_DETECTED,
                        NotificationSeverity.WARNING,
                        NotificationMessageKey.PENDING_DEPOSIT_DETECTED,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        creditMeta(
                                transactionId,
                                walletId,
                                rail == null ? "ONCHAIN" : rail,
                                creditedSats,
                                confirmations,
                                "INBOUND"),
                        satsToBtc(creditedSats)));
    }

    @Override
    public void notifyDepositConfirmationProgress(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long creditedSats,
            int confirmations) {
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.DEPOSIT_DETECTED,
                        NotificationSeverity.WARNING,
                        NotificationMessageKey.PENDING_DEPOSIT_PROGRESS,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        creditMeta(transactionId, walletId, rail, creditedSats, confirmations, "INBOUND"),
                        satsToBtc(creditedSats),
                        String.valueOf(confirmations)));
    }

    @Override
    public void notifyOutboundDetected(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long amountSats,
            int confirmations,
            String destinationHint) {
        Map<String, String> meta = debitMeta(
                transactionId,
                walletId,
                rail == null ? "ONCHAIN" : rail,
                amountSats,
                confirmations);
        if (destinationHint != null && !destinationHint.isBlank()) {
            meta.put("destination", destinationHint);
        }
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.PAYMENT_SENT,
                        NotificationSeverity.WARNING,
                        NotificationMessageKey.COLD_OUTBOUND_DETECTED,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        meta,
                        satsToBtc(amountSats)));
    }

    @Override
    public void notifyOutboundConfirmed(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long amountSats,
            int confirmations) {
        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.PAYMENT_SENT,
                        NotificationSeverity.SUCCESS,
                        NotificationMessageKey.COLD_OUTBOUND_CONFIRMED,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        debitMeta(
                                transactionId,
                                walletId,
                                rail == null ? "ONCHAIN" : rail,
                                amountSats,
                                confirmations),
                        satsToBtc(amountSats)));
    }

    @Override
    public void notifyInternalTransferReceived(
            Long receiverUserId,
            UUID transactionId,
            UUID walletId,
            long amountSats) {
        notificationService.notifyUser(
                receiverUserId,
                NotificationMessages.payload(
                        NotificationKind.TRANSFER_RECEIVED,
                        NotificationSeverity.SUCCESS,
                        NotificationMessageKey.INTERNAL_TRANSFER_RECEIVED,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        creditMeta(transactionId, walletId, "INTERNAL", amountSats, null, "INBOUND"),
                        satsToBtc(amountSats)));
    }

    @Override
    public void notifyInternalTransferSent(
            Long senderUserId,
            UUID transactionId,
            UUID walletId,
            long amountSats) {
        notificationService.notifyUser(
                senderUserId,
                NotificationMessages.payload(
                        NotificationKind.PAYMENT_SENT,
                        NotificationSeverity.SUCCESS,
                        NotificationMessageKey.INTERNAL_TRANSFER_SENT,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        debitMeta(transactionId, walletId, "INTERNAL", amountSats, 0),
                        satsToBtc(amountSats)));
    }

    @Override
    public void notifyExternalPaymentSent(
            Long userId,
            UUID transactionId,
            UUID walletId,
            String rail,
            long amountSats) {
        NotificationMessageKey messageKey = "LIGHTNING".equalsIgnoreCase(rail)
                ? NotificationMessageKey.EXTERNAL_LIGHTNING_PAYMENT_SENT
                : NotificationMessageKey.EXTERNAL_ONCHAIN_PAYMENT_SENT;

        notificationService.notifyUser(
                userId,
                NotificationMessages.payload(
                        NotificationKind.PAYMENT_SENT,
                        NotificationSeverity.SUCCESS,
                        messageKey,
                        "/home",
                        "transaction",
                        transactionId.toString(),
                        debitMeta(transactionId, walletId, rail == null ? "ONCHAIN" : rail, amountSats, 0),
                        satsToBtc(amountSats)));
    }

    private NotificationMessageKey depositMessageKey(String rail) {
        return "LIGHTNING".equalsIgnoreCase(rail)
                ? NotificationMessageKey.EXTERNAL_LIGHTNING_DEPOSIT_CONFIRMED
                : NotificationMessageKey.EXTERNAL_ONCHAIN_DEPOSIT_CONFIRMED;
    }

    private Map<String, String> creditMeta(
            UUID transactionId,
            UUID walletId,
            String rail,
            long creditedSats,
            Integer confirmations,
            String direction) {
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("transactionId", transactionId.toString());
        meta.put("walletId", walletId.toString());
        meta.put("rail", rail == null ? "ONCHAIN" : rail);
        meta.put("creditedSats", String.valueOf(creditedSats));
        meta.put("amountSats", String.valueOf(creditedSats));
        meta.put("amountBtc", satsToBtc(creditedSats));
        if (confirmations != null) {
            meta.put("confirmations", String.valueOf(confirmations));
        }
        if (direction != null) {
            meta.put("direction", direction);
        }
        return meta;
    }

    private Map<String, String> debitMeta(
            UUID transactionId,
            UUID walletId,
            String rail,
            long amountSats,
            int confirmations) {
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("transactionId", transactionId.toString());
        meta.put("walletId", walletId.toString());
        meta.put("rail", rail);
        meta.put("amountSats", String.valueOf(amountSats));
        meta.put("amountBtc", satsToBtc(amountSats));
        meta.put("confirmations", String.valueOf(confirmations));
        meta.put("direction", "OUTBOUND");
        return meta;
    }

    private String satsToBtc(long sats) {
        return BigDecimal.valueOf(sats)
                .divide(BigDecimal.valueOf(100_000_000L), 8, RoundingMode.UNNECESSARY)
                .stripTrailingZeros()
                .toPlainString();
    }
}
