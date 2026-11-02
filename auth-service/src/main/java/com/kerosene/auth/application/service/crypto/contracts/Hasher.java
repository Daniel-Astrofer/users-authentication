package com.kerosene.auth.application.service.crypto.contracts;

/** Boundary for one-way hashing of sensitive character input and subsequent verification. */
public interface Hasher {

    /**
     * Hashes sensitive input using the implementation's configured algorithm and secret material.
     * Implementations may consume or clear the supplied character array; callers must not assume it remains intact.
     *
     * @param input sensitive characters to hash
     * @return encoded hash containing the metadata required by the matching verification implementation
     */
    String hash(char[] input);

    /**
     * Verifies candidate input against an encoded hash using the same algorithm and secret material.
     * Implementations may clear the candidate buffer as part of verification.
     *
     * @param input candidate sensitive characters
     * @param hash previously encoded hash, including algorithm metadata and salt where applicable
     * @return whether the candidate matches the encoded value
     */
    Boolean verify(char[] input, String hash);
}
