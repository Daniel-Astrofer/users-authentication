package com.kerosene.auth.application.service.devicekey;

/** Signals that an Ed25519 device-key signature is invalid or cannot be verified. */
public class DeviceKeySignatureException extends DeviceKeyProtocolException {
    /** Creates a signature rejection.
     * @param message signature failure detail
     */
    public DeviceKeySignatureException(String message) {
        super(message);
    }

    /** Creates a signature failure while preserving the underlying crypto exception.
     * @param message verification failure detail
     * @param cause cryptographic provider or key parsing failure
     */
    public DeviceKeySignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
