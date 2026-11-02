package com.kerosene.auth.model.enums;

/** Outcomes that may be persisted for an administrator access audit event. */
public enum AdminAccessEventStatus {
    /** An authorized administrator approved the access attempt. */
    APPROVED,
    /** An authorized administrator explicitly rejected the access attempt. */
    DENIED,
    /** A policy or administrator blocked the attempt from continuing. */
    BLOCKED
}
