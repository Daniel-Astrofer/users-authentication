package com.kerosene.auth.dto.devicebinding;

/**
 * Payload returned when a deviceInstallId is already bound to another account.
 * Client must re-submit registration with confirmUnlinkDevice=true after user consent.
 * The masked previous username is informational only and must not be used as an account identifier.
 *
 * @param action machine-readable next action; currently {@value #ACTION_CONFIRM_UNLINK}
 * @param deviceInstallId identifier of the device whose existing binding needs confirmation
 * @param previousUsernameMasked privacy-preserving label of the account currently bound to the device
 * @param message user-facing explanation of the conflict
 * @param guidance user-facing consequence and confirmation instructions
 */
public record DeviceAlreadyBoundDTO(
        String action,
        String deviceInstallId,
        String previousUsernameMasked,
        String message,
        String guidance) {

    public static final String ACTION_CONFIRM_UNLINK = "CONFIRM_UNLINK_DEVICE";

    /**
     * Creates the conflict response and substitutes a generic label when no masked username exists.
     *
     * @param deviceInstallId device identifier submitted by the client
     * @param previousUsernameMasked already-masked label for the currently linked account, if available
     * @return response requiring explicit consent before the prior device binding is removed
     */
    public static DeviceAlreadyBoundDTO of(String deviceInstallId, String previousUsernameMasked) {
        String masked = previousUsernameMasked == null || previousUsernameMasked.isBlank()
                ? "outra conta"
                : previousUsernameMasked;
        return new DeviceAlreadyBoundDTO(
                ACTION_CONFIRM_UNLINK,
                deviceInstallId,
                masked,
                "Este aparelho ja esta vinculado a outra conta (" + masked + ").",
                "Ao continuar, a passkey/device-key da conta anterior sera removida deste dispositivo "
                        + "e ela so podera ser acessada com senha. Confirme para criar a nova conta neste aparelho.");
    }
}
