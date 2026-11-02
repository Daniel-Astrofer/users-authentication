package com.kerosene.auth.application.service.devicebinding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.DeviceKeyCredentialRepository;
import com.kerosene.auth.application.infra.persistence.jpa.PasskeyCredentialRepository;
import com.kerosene.auth.dto.devicebinding.DeviceAlreadyBoundDTO;
import com.kerosene.auth.model.entity.DeviceKeyCredential;
import com.kerosene.auth.model.entity.PasskeyCredential;
import com.kerosene.common.infra.logging.LogDomain;
import com.kerosene.common.infra.logging.LogSanitizer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Unified device↔account binding policy for passkey and device-key credentials.
 *
 * <p>Rules:
 * <ul>
 *   <li>One device ({@code deviceInstallId}) may be bound to at most one account.</li>
 *   <li>One account may have many devices.</li>
 *   <li>Rebinding a device to a different account requires explicit {@code confirmUnlinkDevice}
 *       and deletes the previous account's credentials for that install from the database.</li>
 * </ul>
 */
@Service
public class DeviceBindingPolicy {

    private static final Logger log = LoggerFactory.getLogger(DeviceBindingPolicy.class);

    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final DeviceKeyCredentialRepository deviceKeyCredentialRepository;

    /**
     * Creates the binding policy over the two credential stores that claim device installations.
     *
     * @param passkeyCredentialRepository passkey credential lookup and deletion boundary
     * @param deviceKeyCredentialRepository device-key credential lookup and deletion boundary
     */
    public DeviceBindingPolicy(
            PasskeyCredentialRepository passkeyCredentialRepository,
            DeviceKeyCredentialRepository deviceKeyCredentialRepository) {
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.deviceKeyCredentialRepository = deviceKeyCredentialRepository;
    }

    /**
     * Read-only conflict probe. Runs outside any outer write transaction so callers can return
     * AUTH_024 without marking the outer TX rollback-only.
     *
     * @param deviceInstallId submitted install identifier, optionally absent
     * @param targetUserId account attempting to claim the install; null during signup
     * @return masked conflict payload for a different active owner, or null if there is no conflict
     */
    @Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)
    public DeviceAlreadyBoundDTO findBindingConflict(String deviceInstallId, Long targetUserId) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null) {
            return null;
        }
        DeviceOwner owner = findActiveOwner(installId);
        if (owner == null) {
            return null;
        }
        if (targetUserId != null && Objects.equals(owner.userId(), targetUserId)) {
            return null;
        }
        return DeviceAlreadyBoundDTO.of(installId, maskUsername(owner.username()));
    }

    /**
     * Ensures the install can be bound to {@code targetUserId} (null during signup before user exists).
     * When another account owns the install and {@code confirmUnlinkDevice} is false, returns a
     * {@link DeviceAlreadyBoundDTO} without throwing (avoids Spring rollback-only on checked conflict).
     * When true, deletes all credentials on that install that do not belong to the target user
     * (or all credentials when target is null / signup).
     *
     * @param deviceInstallId install identifier being claimed
     * @param targetUserId account claiming the install, or null before account creation
     * @param confirmUnlinkDevice whether the user explicitly confirmed removal of the prior binding
     * @return null if binding may proceed; otherwise the conflict payload for AUTH_024
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public DeviceAlreadyBoundDTO ensureDeviceAvailableForBind(
            String deviceInstallId,
            Long targetUserId,
            boolean confirmUnlinkDevice) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null) {
            return null;
        }

        DeviceOwner owner = findActiveOwner(installId);
        if (owner == null) {
            return null;
        }

        if (targetUserId != null && Objects.equals(owner.userId(), targetUserId)) {
            // Same account re-registering on this device: replace credentials for this install only.
            deleteCredentialsForInstallExceptUser(installId, targetUserId);
            deleteCredentialsForUserAndInstall(installId, targetUserId);
            return null;
        }

        // Owned by another account (or any account during pre-user signup).
        if (!confirmUnlinkDevice) {
            return DeviceAlreadyBoundDTO.of(installId, maskUsername(owner.username()));
        }

        int removed = deleteAllCredentialsForInstall(installId);
        log.info(
                LogDomain.AUTH,
                "event=DEVICE_BINDING_UNLINK deviceInstallRef={} previousUserRef={} removedCredentials={} targetUserRef={}",
                LogSanitizer.fingerprint(installId),
                LogSanitizer.fingerprint(owner.username()),
                removed,
                targetUserId == null ? "signup" : LogSanitizer.fingerprint(String.valueOf(targetUserId)));
        return null;
    }

    /**
     * After recovery rotation deletes all user passkeys, clear any device-key leftovers for installs
     * that will be rebound — recovery already replaces passkeys; also wipe device-keys for those installs
     * owned only by this user is handled by delete-all passkeys. Call when a new credential is about
     * to claim an install after full user credential wipe.
     *
     * @param deviceInstallId installation identifier to make available to the recovering account
     * @param recoveringUserId recovering account identifier
     */
    @Transactional
    public void releaseInstallForRecovery(String deviceInstallId, Long recoveringUserId) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null) {
            return;
        }
        // Drop foreign bindings so the recovering user can claim the device.
        ensureDeviceAvailableForBind(installId, recoveringUserId, true);
    }

    /**
     * Finds the first account owning an active passkey or device-key credential for this installation.
     * Passkeys are checked before device keys; missing, blank, or inactive credential status is treated
     * as active by the legacy {@link #isActive(String)} compatibility rule.
     *
     * @param deviceInstallId install identifier to search
     * @return owner projection, or null when no active credential is found
     */
    public DeviceOwner findActiveOwner(String deviceInstallId) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null) {
            return null;
        }

        List<PasskeyCredential> passkeys =
                passkeyCredentialRepository.findActiveByDeviceInstallId(installId);
        for (PasskeyCredential credential : passkeys) {
            if (credential.getUser() != null && isActive(credential.getStatus())) {
                return new DeviceOwner(
                        credential.getUser().getId(),
                        credential.getUser().getUsername());
            }
        }

        List<DeviceKeyCredential> deviceKeys =
                deviceKeyCredentialRepository.findActiveByDeviceInstallId(installId);
        for (DeviceKeyCredential credential : deviceKeys) {
            if (credential.getUser() != null && isActive(credential.getStatus())) {
                return new DeviceOwner(
                        credential.getUser().getId(),
                        credential.getUser().getUsername());
            }
        }
        return null;
    }

    /**
     * Deletes all passkey and device-key credentials associated with a normalized installation ID.
     *
     * @param deviceInstallId install identifier whose credentials are removed
     * @return total number of removed passkey and device-key rows; zero for a missing identifier
     */
    @Transactional
    public int deleteAllCredentialsForInstall(String deviceInstallId) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null) {
            return 0;
        }
        int passkeys = passkeyCredentialRepository.deleteByDeviceInstallId(installId);
        int deviceKeys = deviceKeyCredentialRepository.deleteByDeviceInstallId(installId);
        return passkeys + deviceKeys;
    }

    /**
     * Deletes only this account's passkey and device-key credentials for the installation.
     *
     * @param deviceInstallId install identifier shared by the selected credentials
     * @param userId owner account whose credentials should be removed
     */
    @Transactional
    public void deleteCredentialsForUserAndInstall(String deviceInstallId, Long userId) {
        String installId = normalizeInstallId(deviceInstallId);
        if (installId == null || userId == null) {
            return;
        }
        passkeyCredentialRepository.deleteByUserIdAndDeviceInstallId(userId, installId);
        deviceKeyCredentialRepository.deleteByUserIdAndDeviceInstallId(userId, installId);
    }

    /** Deletes active credentials on the installation whose owner differs from the retained account. */
    private void deleteCredentialsForInstallExceptUser(String installId, Long userId) {
        List<PasskeyCredential> passkeys =
                passkeyCredentialRepository.findActiveByDeviceInstallId(installId);
        List<PasskeyCredential> foreignPasskeys = new ArrayList<>();
        for (PasskeyCredential credential : passkeys) {
            if (credential.getUser() == null || !Objects.equals(credential.getUser().getId(), userId)) {
                foreignPasskeys.add(credential);
            }
        }
        if (!foreignPasskeys.isEmpty()) {
            passkeyCredentialRepository.deleteAll(foreignPasskeys);
        }

        List<DeviceKeyCredential> deviceKeys =
                deviceKeyCredentialRepository.findActiveByDeviceInstallId(installId);
        List<DeviceKeyCredential> foreignKeys = new ArrayList<>();
        for (DeviceKeyCredential credential : deviceKeys) {
            if (credential.getUser() == null || !Objects.equals(credential.getUser().getId(), userId)) {
                foreignKeys.add(credential);
            }
        }
        if (!foreignKeys.isEmpty()) {
            deviceKeyCredentialRepository.deleteAll(foreignKeys);
        }
    }

    /**
     * Trims the installation identifier and maps null or blank values to null.
     *
     * @param deviceInstallId raw install identifier supplied by the caller
     * @return trimmed identifier, or null when absent
     */
    public static String normalizeInstallId(String deviceInstallId) {
        if (deviceInstallId == null) {
            return null;
        }
        String trimmed = deviceInstallId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Masks a username for conflict responses while retaining at most a short prefix and final character.
     *
     * @param username account name to mask
     * @return masked value; blank input becomes {@code ***}
     */
    public static String maskUsername(String username) {
        if (username == null || username.isBlank()) {
            return "***";
        }
        String normalized = username.trim();
        if (normalized.length() <= 2) {
            return normalized.charAt(0) + "***";
        }
        if (normalized.length() <= 4) {
            return normalized.substring(0, 1) + "***" + normalized.substring(normalized.length() - 1);
        }
        return normalized.substring(0, 2) + "***" + normalized.substring(normalized.length() - 1);
    }

    /** Treats null/blank legacy status as active and otherwise accepts only the ACTIVE label. */
    private static boolean isActive(String status) {
        return status == null
                || status.isBlank()
                || "ACTIVE".equalsIgnoreCase(status.trim());
    }

    /**
     * Minimal owner details used to report an existing device binding without exposing credential data.
     *
     * @param userId owning account identifier
     * @param username account name, which must be masked before being returned to a different account
     */
    public record DeviceOwner(Long userId, String username) {}
}
