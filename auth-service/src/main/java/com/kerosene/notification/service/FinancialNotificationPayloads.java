package com.kerosene.notification.service;

import com.kerosene.common.financial.notification.FinancialNotificationEventRequest;
import com.kerosene.notification.model.NotificationKind;
import com.kerosene.notification.l10n.NotificationMessageKey;
import com.kerosene.notification.l10n.NotificationMessages;
import com.kerosene.notification.model.NotificationSeverity;
import com.kerosene.notification.model.UserNotificationPayload;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

/** Maps facts to presentation; provider error messages are never copied into notifications. */
public final class FinancialNotificationPayloads {
    private FinancialNotificationPayloads() {}

    public static UserNotificationPayload from(FinancialNotificationEventRequest event) {
        NotificationKind kind;
        NotificationSeverity severity = NotificationSeverity.INFO;
        String status;
        NotificationMessageKey messageKey;
        switch (event.type()) {
            case DEPOSIT_DETECTED, DEPOSIT_CONFIRMATION_PROGRESS, DEPOSIT_UNDERPAID -> {
                kind = NotificationKind.DEPOSIT_DETECTED; status = "validating"; messageKey = NotificationMessageKey.FINANCIAL_RECEIVE_DETECTED;
            }
            case DEPOSIT_CONFIRMED, DEPOSIT_FINALIZED, DEPOSIT_RECONCILED, PAYMENT_REQUEST_DEPOSIT_CONFIRMED -> {
                kind = NotificationKind.DEPOSIT_CONFIRMED; status = "confirmed"; messageKey = NotificationMessageKey.FINANCIAL_RECEIVE_CONFIRMED;
                severity = NotificationSeverity.SUCCESS;
            }
            case INTERNAL_TRANSFER_RECEIVED -> {
                kind = NotificationKind.TRANSFER_RECEIVED; status = "confirmed"; messageKey = NotificationMessageKey.FINANCIAL_RECEIVE_CONFIRMED;
                severity = NotificationSeverity.SUCCESS;
            }
            case INTERNAL_TRANSFER_SENT -> {
                kind = NotificationKind.TRANSFER_SENT; status = "confirmed"; messageKey = NotificationMessageKey.FINANCIAL_SEND_CONFIRMED;
                severity = NotificationSeverity.SUCCESS;
            }
            case PAYMENT_PROCESSING, PAYMENT_IN_FLIGHT -> {
                kind = NotificationKind.PAYMENT_PROCESSING; status = "processing"; messageKey = NotificationMessageKey.FINANCIAL_SEND_PROCESSING;
            }
            case PAYMENT_BROADCAST, PAYMENT_REPLACED -> {
                kind = NotificationKind.PAYMENT_BROADCAST; status = "broadcasted"; messageKey = NotificationMessageKey.FINANCIAL_SEND_BROADCAST;
            }
            case PAYMENT_CONFIRMED -> {
                kind = NotificationKind.PAYMENT_CONFIRMED; status = "confirmed"; messageKey = NotificationMessageKey.FINANCIAL_SEND_CONFIRMED;
                severity = NotificationSeverity.SUCCESS;
            }
            case PAYMENT_FAILED -> {
                kind = NotificationKind.PAYMENT_FAILED; status = "failed"; messageKey = NotificationMessageKey.FINANCIAL_SEND_FAILED;
                severity = NotificationSeverity.ERROR;
            }
            case DEPOSIT_DROPPED -> {
                kind = NotificationKind.DEPOSIT_DROPPED; status = "dropped"; messageKey = NotificationMessageKey.FINANCIAL_RECEIVE_DROPPED;
                severity = NotificationSeverity.WARNING;
            }
            case DEPOSIT_REVERSED -> {
                kind = NotificationKind.DEPOSIT_REVERSED; status = "reversed"; messageKey = NotificationMessageKey.FINANCIAL_RECEIVE_REVERSED;
                severity = NotificationSeverity.WARNING;
            }
            case DEPOSIT_CONFLICTED, PAYMENT_CONFLICTED, PAYMENT_RECONCILIATION_REQUIRED -> {
                kind = NotificationKind.PAYMENT_RECONCILIATION_REQUIRED;
                status = "requires_reconciliation"; messageKey = NotificationMessageKey.FINANCIAL_RECONCILIATION;
                severity = NotificationSeverity.WARNING;
            }
            default -> throw new IllegalArgumentException("Unsupported financial event type.");
        }
        Map<String, String> metadata = new LinkedHashMap<>();
        metadata.put("eventId", event.eventId().toString());
        metadata.put("dedupeKey", event.eventId().toString());
        metadata.put("transactionId", event.transactionId().toString());
        metadata.put("walletId", event.walletId().toString());
        metadata.put("rail", event.rail());
        metadata.put("amountSats", Long.toString(event.amountSats()));
        metadata.put("amountBtc", BigDecimal.valueOf(event.amountSats(), 8).toPlainString());
        metadata.put("confirmations", Integer.toString(event.confirmations()));
        metadata.put("status", status);
        metadata.put("eventSequence", Long.toString(event.eventSequence()));
        metadata.put("eventType", event.type().name());
        metadata.put("schemaVersion", Integer.toString(event.schemaVersion()));
        metadata.put("occurredAt", event.occurredAt().toString());
        if (event.networkReference() != null) metadata.put("networkReference", event.networkReference());
        if (event.failureCode() != null) metadata.put("failureCode", event.failureCode());
        if (event.paymentRequestId() != null) metadata.put("paymentRequestId", event.paymentRequestId().toString());
        if (event.publicId() != null) metadata.put("publicId", event.publicId());
        String occurred = event.occurredAt().toString();
        var message = NotificationMessages.resolve(messageKey);
        return new UserNotificationPayload(event.eventId().toString(), kind.wireValue(), severity.wireValue(),
                message.title(), message.body(), occurred, occurred,
                "/home", "transaction", event.transactionId().toString(), metadata);
    }
}
