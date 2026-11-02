package com.kerosene.auth.application.service.crypto.encrypter;

import com.kerosene.auth.application.service.crypto.contracts.Cryptography;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

/** Encrypts secret bytes with AES-GCM and stores the 12-byte nonce before the authenticated ciphertext. */
@Component("aes256")
public class AES256 implements Cryptography {

    /** Creates an AES-GCM encryptor; each encryption call creates a fresh nonce. */
    public AES256() {
    }


    /**
     * Encrypts bytes with AES/GCM/NoPadding using a fresh random 96-bit nonce and 128-bit tag.
     * The nonce is prefixed to the ciphertext so {@link #decrypt(byte[], SecretKey)} can recover it.
     *
     * @param totpSecret plaintext bytes, commonly a TOTP secret
     * @param key AES key supplied by the secure key provider
     * @return concatenation of nonce and authenticated ciphertext
     * @throws Exception if the cipher cannot initialize or encrypt
     */
    public byte[] encrypt(byte[] totpSecret, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");


        byte[] totp = totpSecret;

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] criptoText = cipher.doFinal(totp);
        byte[] combined = new byte[iv.length + criptoText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(criptoText, 0, combined, iv.length, criptoText.length);
        return combined;

    }

    /**
     * Splits the 12-byte nonce prefix from the payload and authenticates/decrypts the ciphertext.
     * GCM authentication failure is propagated by the cipher; truncated input also fails during parsing.
     *
     * @param hash concatenated nonce and AES-GCM ciphertext with authentication tag
     * @param key AES key corresponding to the encryption key
     * @return recovered plaintext bytes
     * @throws Exception for truncated, tampered, or otherwise invalid ciphertext or key
     */
    public byte[] decrypt(byte[] hash, SecretKey key) throws Exception {

        byte[] iv = Arrays.copyOfRange(hash, 0, 12);
        byte[] cipherText = Arrays.copyOfRange(hash, 12, hash.length);


        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);


        return cipher.doFinal(cipherText);
    }


}
