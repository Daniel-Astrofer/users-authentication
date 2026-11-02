package com.kerosene.auth.dto;

import java.util.List;

/** Response returned after recovery rotates credentials and invalidates prior recovery material. */
public class EmergencyRecoveryFinishResponse {

    /** Account name restored by the completed recovery operation. */
    private String username;
    /** Newly generated one-time backup codes; the user must save them because they are shown only once. */
    private List<String> newBackupCodes;

    /** Newly persisted canonical credential, when completion used Device Key. */
    private String deviceKeyCredentialId;

    public String getDeviceKeyCredentialId() { return deviceKeyCredentialId; }

    public void setDeviceKeyCredentialId(String deviceKeyCredentialId) {
        this.deviceKeyCredentialId = deviceKeyCredentialId;
    }

    /** Creates an empty response for serializer-based binding. */
    public EmergencyRecoveryFinishResponse() {
    }

    /** Creates the completed-recovery response.
     * @param username recovered account name
     * @param newBackupCodes replacement one-time backup codes
     */
    public EmergencyRecoveryFinishResponse(String username, List<String> newBackupCodes) {
        this.username = username;
        this.newBackupCodes = newBackupCodes;
    }

    /** Returns the account name whose credentials were recovered.
     * @return recovered account name
     */
    public String getUsername() {
        return username;
    }

    /** Sets the recovered account name.
     * @param username account name
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /** Returns replacement recovery codes that must be saved by the user.
     * @return newly generated one-time codes
     */
    public List<String> getNewBackupCodes() {
        return newBackupCodes;
    }

    /** Sets the replacement recovery codes.
     * @param newBackupCodes new one-time code values
     */
    public void setNewBackupCodes(List<String> newBackupCodes) {
        this.newBackupCodes = newBackupCodes;
    }
}
