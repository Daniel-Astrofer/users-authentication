package com.kerosene.auth.application.port.out;

import java.util.List;

import com.kerosene.auth.model.entity.PasskeyCredential;

/** Outbound persistence port for account-owned WebAuthn passkey credentials. */
public interface AuthPasskeyGateway {

    /**
     * Lists all persisted passkey credentials associated with one account.
     *
     * @param userId account identifier used to scope the credential lookup
     * @return credentials owned by the account
     */
    List<PasskeyCredential> findByUserId(Long userId);

    /**
     * Deletes the supplied persisted passkey rows.
     *
     * @param credentials credential entities selected for deletion by the caller
     */
    void deleteAll(List<PasskeyCredential> credentials);

    /**
     * Persists one credential and returns the stored representation, including generated fields.
     *
     * @param credential credential with owner and public authenticator data; private keys are not stored here
     * @return persisted credential
     */
    PasskeyCredential save(PasskeyCredential credential);
}
