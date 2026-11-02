package com.kerosene.platform.util;

import java.util.Base64;

/** Base64 decoding helpers shared by authentication and cryptographic integrations. */
public class CryptoUtils {

    /** Prevents construction of this stateless utility class. */
    private CryptoUtils() {}

    /**
     * Loosely decodes a Base64 string, trying Standard and then URL-safe decoders.
     * Handles both padded and unpadded input.
     *
     * @param value The Base64 string.
     * @return The decoded bytes.
     * @throws IllegalArgumentException if the input is not a valid Base64 string.
     */
    public static byte[] decodeBase64(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        // Try standard first as it's the default for many libs
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            // Try URL-safe decoder (lenient with padding if we use the right one)
            try {
                return Base64.getUrlDecoder().decode(value);
            } catch (IllegalArgumentException e2) {
                // Try unpadded versions if padded failed
                String unpadded = value.replaceAll("=+$", "");
                try {
                    return Base64.getDecoder().decode(unpadded);
                } catch (IllegalArgumentException e3) {
                    return Base64.getUrlDecoder().decode(unpadded);
                }
            }
        }
    }
}
