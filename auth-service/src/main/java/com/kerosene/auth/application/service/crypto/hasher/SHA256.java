package com.kerosene.auth.application.service.crypto.hasher;

import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.nio.CharBuffer;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** Derives a deterministic, peppered HMAC-SHA256 representation for legacy bcrypt storage. */
@Component("SHAHasher")
public class SHA256 implements Hasher {

    /** Deployment secret used as the HMAC key; it is not embedded in the derived value. */
    private final String hardwareKey;

    /**
     * Stores the configured secret for keyed digest operations.
     *
     * @param hardwareKey pepper loaded from secret configuration
     */
    public SHA256(@Value("${api.secret.pepper.secret}") String hardwareKey) {
        this.hardwareKey = hardwareKey;
    }

    /**
     * Derives a Base64 HMAC-SHA256 value. The temporary UTF-8 byte buffer is cleared on the successful path;
     * this implementation does not clear the caller's character array.
     *
     * @param input sensitive characters used as the HMAC message
     * @return Base64 encoded keyed digest
     * @throws RuntimeException when the HMAC provider cannot perform the operation
     */
    public String hash(char[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(hardwareKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);

            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(input));
            byte[] inputBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(inputBytes);

            byte[] hash = mac.doFinal(inputBytes);

            Arrays.fill(inputBytes, (byte) 0);
            Arrays.fill(byteBuffer.array(), (byte) 0);

            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error generating HMAC-SHA256", e);
        }
    }

    /**
     * Compares the deterministic keyed digest to a stored value.
     *
     * @param passphrase candidate sensitive characters; the hash method does not clear this array
     * @param hash expected Base64 digest
     * @return whether the derived value equals the expected digest
     */
    @Override
    public Boolean verify(char[] passphrase, String hash) {
        String pass = hash(passphrase);
        return pass.equals(hash);
    }

}
