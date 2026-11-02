package com.kerosene.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Write-only administrator-key enrollment data scoped to a device installation. */
public class AdminKeyCreateRequestDTO {

    /** Creates an empty request bean for JSON deserialization. */
    public AdminKeyCreateRequestDTO() {
    }

    /** write-only administrator key material hash used to enroll the client key proof */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String keyMaterialHash;
    /** stable installation identity to which this administrator key is bound */
    private String deviceInstallId;

    /**
     * Returns write-only administrator key material hash used to enroll the client key proof
     * @return key material hash
     */
    public String getKeyMaterialHash() { return keyMaterialHash; }

    /**
     * Sets write-only administrator key material hash used to enroll the client key proof
     * @param keyMaterialHash key material hash
     */
    public void setKeyMaterialHash(String keyMaterialHash) { this.keyMaterialHash = keyMaterialHash; }

    /**
     * Returns stable installation identity to which this administrator key is bound
     * @return device installation ID
     */
    public String getDeviceInstallId() { return deviceInstallId; }

    /**
     * Sets stable installation identity to which this administrator key is bound
     * @param deviceInstallId device installation ID
     */
    public void setDeviceInstallId(String deviceInstallId) { this.deviceInstallId = deviceInstallId; }

}
