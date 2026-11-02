package com.kerosene.auth.application.service.devicekey;

/** Signals that a device-key challenge is missing, expired, invalid, or already consumed. */
public class DeviceKeyChallengeException extends DeviceKeyProtocolException {
    /**
     * Creates the challenge failure with an explanatory message.
     *
     * @param message challenge failure detail used by the protocol error mapper
     */
    public DeviceKeyChallengeException(String message) {
        super(message);
    }
}
