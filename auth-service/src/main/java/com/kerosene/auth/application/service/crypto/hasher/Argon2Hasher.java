package com.kerosene.auth.application.service.crypto.hasher;

import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

/** Password hasher using Argon2id parameters and a server-side pepper appended to each passphrase. */
@Component("Argon2Hasher")
public class Argon2Hasher implements Hasher {

    /** Argon2 encoder configured with 64 MiB memory, three iterations, four lanes, and 16-byte salts. */
    private final Argon2PasswordEncoder encoder;
    /** Secret pepper kept outside the encoded hash and loaded from deployment configuration. */
    private final String pepper;

    /**
     * Builds the Argon2id encoder and rejects missing pepper configuration during application startup.
     *
     * @param pepper server-side secret appended to each passphrase before hashing and verification
     * @throws IllegalStateException when no nonblank pepper is configured
     */
    public Argon2Hasher(@Value("${api.secret.pepper.secret}") String pepper) {
        if (pepper == null || pepper.isBlank()) {
            throw new IllegalStateException("[Security] api.secret.pepper.secret is not configured.");
        }
        this.pepper = pepper;

        // Iterations=3, Memory=65536 (64MB), Parallelism=4, Length=32, SaltLength=16
        this.encoder = new Argon2PasswordEncoder(16, 32, 4, 65536, 3);
    }

    /**
     * Hashes the passphrase with the configured pepper, then clears the caller array and temporary character arrays.
     * The resulting value embeds the salt and Argon2 parameters needed for later verification.
     *
     * @param passphrase sensitive characters; the supplied array is zeroed before this method returns
     * @return Argon2 encoded hash with salt and algorithm parameters
     */
    @Override
    public String hash(char[] passphrase) {
        char[] pepperChars = this.pepper.toCharArray();
        char[] passChars = passphrase;
        char[] combined = new char[passChars.length + pepperChars.length];

        System.arraycopy(passChars, 0, combined, 0, passChars.length);
        System.arraycopy(pepperChars, 0, combined, passChars.length, pepperChars.length);

        try {
            java.nio.CharBuffer buffer = java.nio.CharBuffer.wrap(combined);
            return encoder.encode(buffer);
        } finally {
            java.util.Arrays.fill(combined, '\0');
            java.util.Arrays.fill(pepperChars, '\0');
            java.util.Arrays.fill(passChars, '\0');
        }
    }

    /**
     * Checks a passphrase against the encoded Argon2 hash and clears the supplied and temporary character arrays.
     *
     * @param passphrase candidate sensitive characters; the supplied array is zeroed before return
     * @param hash previously encoded Argon2 value
     * @return whether the passphrase matches
     */
    @Override
    public Boolean verify(char[] passphrase, String hash) {
        char[] pepperChars = this.pepper.toCharArray();
        char[] passChars = passphrase;
        char[] combined = new char[passChars.length + pepperChars.length];

        System.arraycopy(passChars, 0, combined, 0, passChars.length);
        System.arraycopy(pepperChars, 0, combined, passChars.length, pepperChars.length);

        try {
            java.nio.CharBuffer buffer = java.nio.CharBuffer.wrap(combined);
            return encoder.matches(buffer, hash);
        } finally {
            java.util.Arrays.fill(combined, '\0');
            java.util.Arrays.fill(pepperChars, '\0');
            java.util.Arrays.fill(passChars, '\0');
        }
    }
}
