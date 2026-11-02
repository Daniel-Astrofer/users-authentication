package com.kerosene.auth.model.enums;

/** Trust lifecycle for a device enrolled to participate in administrator authentication. */
public enum AdminAccessDeviceStatus {
    /** Device enrollment is trusted and may be used by the administrator access workflow. */
    ACTIVE,
    /** Enrollment exists but has not yet completed its trust or approval process. */
    PENDING,
    /** Device is temporarily barred from administrator authentication. */
    BLOCKED,
    /** Trust was permanently revoked; the device must be enrolled again to regain access. */
    REVOKED
}
