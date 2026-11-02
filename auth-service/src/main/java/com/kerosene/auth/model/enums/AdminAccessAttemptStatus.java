package com.kerosene.auth.model.enums;

/** Lifecycle states for a device-bound administrator access attempt. */
public enum AdminAccessAttemptStatus {
    /** Request is awaiting a decision and remains valid until its expiry time. */
    PENDING,
    /** A trusted administrator device approved the request; the requester may redeem it. */
    APPROVED,
    /** The requester consumed the approval to establish the authorized admin session. */
    REDEEMED,
    /** A trusted administrator explicitly refused the request. */
    DENIED,
    /** A security policy prevented further approval or redemption of the attempt. */
    BLOCKED,
    /** The request's approval window elapsed before successful redemption. */
    EXPIRED
}
