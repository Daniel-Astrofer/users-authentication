package com.kerosene.notification.model;

public enum NotificationKind {
    SYSTEM_INFO("system_info"),
    SECURITY_LOGIN_DETECTED("security_login_detected"),
    SECURITY_ADMIN_ACCESS_ATTEMPT("security_admin_access_attempt"),
    SECURITY_RECOVERY_COMPLETED("security_recovery_completed"),
    ACCOUNT_CREATED("account_created"),
    TRANSFER_RECEIVED("transfer_received"),
    TRANSFER_SENT("transfer_sent"),
    PAYMENT_REQUEST_CREATED("payment_request_created"),
    PAYMENT_REQUEST_PAID("payment_request_paid"),
    DEPOSIT_DETECTED("deposit_detected"),
    DEPOSIT_CONFIRMED("deposit_confirmed"),
    PAYMENT_SENT("payment_sent"),
    PAYMENT_PROCESSING("payment_processing"),
    PAYMENT_BROADCAST("payment_broadcast"),
    PAYMENT_CONFIRMED("payment_confirmed"),
    PAYMENT_FAILED("payment_failed"),
    PAYMENT_RECONCILIATION_REQUIRED("payment_reconciliation_required"),
    DEPOSIT_DROPPED("deposit_dropped"),
    DEPOSIT_REVERSED("deposit_reversed");

    private final String wireValue;

    NotificationKind(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static NotificationKind fromValue(String value) {
        if (value == null || value.isBlank()) {
            return SYSTEM_INFO;
        }

        for (NotificationKind kind : values()) {
            if (kind.wireValue.equalsIgnoreCase(value.trim())) {
                return kind;
            }
        }

        return SYSTEM_INFO;
    }
}
