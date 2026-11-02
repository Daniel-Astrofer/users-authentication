package com.kerosene.auth.application.service.devicekey;

/** Signals that a device-key authenticator counter did not advance, indicating a replay or rollback. */
public class DeviceKeyReplayException extends DeviceKeyProtocolException {
    /** Creates the replay failure.
     * @param message replay/counter failure detail
     */
    public DeviceKeyReplayException(String message) {
        super(message);
    }
}
