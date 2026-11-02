package com.kerosene.auth.application.service.devicebinding;

import com.kerosene.auth.dto.devicebinding.DeviceAlreadyBoundDTO;
import com.kerosene.common.exception.ErrorCodes;

/**
 * Raised when a deviceInstallId is owned by another account and confirmUnlinkDevice was not set.
 */
public class DeviceBindingException extends RuntimeException {

    /** Stable response code identifying a device binding conflict. */
    private final String errorCode;
    /** Optional masked conflict details returned to the client for explicit confirmation. */
    private final DeviceAlreadyBoundDTO payload;

    /**
     * Creates a binding conflict carrying the stable error code and masked conflict payload.
     *
     * @param payload safe response data describing the existing binding, if available
     */
    public DeviceBindingException(DeviceAlreadyBoundDTO payload) {
        super(payload == null ? "Device already bound" : payload.message());
        this.errorCode = ErrorCodes.AUTH_DEVICE_ALREADY_BOUND;
        this.payload = payload;
    }

    /**
     * Returns the stable device-already-bound error code.
     *
     * @return stable error code used by API error mapping
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Returns masked details describing the existing device binding.
     *
     * @return conflict payload, or null when no detail was supplied
     */
    public DeviceAlreadyBoundDTO getPayload() {
        return payload;
    }
}
