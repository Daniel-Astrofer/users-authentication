package com.kerosene.auth.model.enums;

/** Lifecycle state of a persisted administrator key enrollment. */
public enum AdminKeyStatus {
    /** Key enrollment is current and may be used for administrator access proof. */
    ACTIVE,
    /** Key was explicitly invalidated and must not authenticate future attempts. */
    REVOKED
}
