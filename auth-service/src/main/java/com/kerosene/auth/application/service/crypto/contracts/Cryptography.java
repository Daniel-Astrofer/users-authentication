package com.kerosene.auth.application.service.crypto.contracts;

import javax.crypto.SecretKey;

/** Symmetric encryption boundary for secret material protected by a caller-supplied key. */
public interface Cryptography {
    /**
     * Encrypts plaintext with the implementation's authenticated format. The encoded result must
     * retain any nonce or other metadata required by {@link #decrypt(byte[], SecretKey)}.
     *
     * @param plaintext secret bytes to protect; callers remain responsible for clearing mutable
     *                  plaintext buffers when their lifecycle requires it
     * @param key symmetric key accepted by the configured implementation
     * @return encoded ciphertext containing the implementation-specific decryption metadata
     * @throws Exception if key initialization, encryption, or output encoding fails
     */
    byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception;

    /**
     * Authenticates and decrypts bytes produced by {@link #encrypt(byte[], SecretKey)}.
     * Implementations must fail closed when ciphertext integrity cannot be established.
     *
     * @param encrypted encoded ciphertext and implementation-required nonce or metadata
     * @param key symmetric key corresponding to the encryption key
     * @return recovered plaintext bytes; the caller owns their secure lifecycle
     * @throws Exception if the key is invalid, the ciphertext is malformed, or authentication fails
     */
    byte[] decrypt(byte[] encrypted, SecretKey key) throws Exception;
}
