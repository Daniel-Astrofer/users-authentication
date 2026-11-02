package com.kerosene.auth.application.service.crypto.hasher;

import com.kerosene.auth.application.service.crypto.contracts.Hasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Legacy-compatible bcrypt hasher that first derives a keyed HMAC-SHA256 representation. */
@Component("BcryptHasher")
public class BcryptHasher implements Hasher {
    /** HMAC pre-hasher that protects low-entropy input before bcrypt's password-length limit. */
    private SHA256 sha256;

    /**
     * Supplies the HMAC implementation used to derive the value consumed by bcrypt.
     *
     * @param sha256 configured keyed HMAC pre-hasher
     */
    public BcryptHasher(SHA256 sha256) {
        this.sha256 = sha256;
    }

    /**
     * Derives a keyed HMAC-SHA256 string and encodes that string with a fresh bcrypt encoder.
     *
     * @param passphrase sensitive input passed to the HMAC implementation
     * @return salted bcrypt encoding of the derived HMAC value
     */
    @Override
    public String hash(char[] passphrase) {
        String pass = sha256.hash(passphrase);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(pass);
    }

    /**
     * Repeats the HMAC derivation and asks bcrypt to verify the resulting value.
     *
     * @param passphrase candidate sensitive input passed to the HMAC implementation
     * @param hash previously encoded bcrypt value
     * @return whether the derived value matches the stored bcrypt encoding
     */
    @Override
    public Boolean verify(char[] passphrase, String hash) {
        String pass = sha256.hash(passphrase);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.matches(pass, hash);
    }

}
