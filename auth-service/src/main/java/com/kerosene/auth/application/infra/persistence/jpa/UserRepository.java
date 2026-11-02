package com.kerosene.auth.application.infra.persistence.jpa;

import com.kerosene.auth.model.entity.UserDataBase;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence queries for authentication users; password verification remains in the service layer. */
@Repository
public interface UserRepository extends JpaRepository<UserDataBase, Long> {

    /** Looks up a user by its canonical username value. */
    UserDataBase findByUsername(String username);

    /** Serializes credential recovery against other transactions locking this account. */
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select u from UserDataBase u where u.username = :username")
    UserDataBase findByUsernameForUpdate(@org.springframework.data.repository.query.Param("username") String username);

    /** Scalar projection used for every authenticated session's revocation check. */
    @org.springframework.data.jpa.repository.Query("select u.credentialEpoch from UserDataBase u where u.id = :userId")
    java.util.Optional<Long> findCredentialEpochById(@org.springframework.data.repository.query.Param("userId") Long userId);

    /** Checks username uniqueness without retrieving the full user row. */
    boolean existsByUsername(String username);

    // ⚠️ existsByUsernameAndPassphrase was intentionally removed.
    // Passing a raw passphrase as a String into JPA leaks it into the JVM String
    // Pool.
    // Password verification MUST occur at the service layer:
    // 1. Retrieve entity with findByUsername(username)
    // 2. Validate with Argon2 / BCrypt against the stored hash using char[]
    // 3. Zero the char[] immediately after validation

}
