package com.kerosene.auth.application.port.out;

import com.kerosene.auth.model.entity.UserDataBase;

/** Outbound persistence port for user lookup, uniqueness checks, and storage. */
public interface AuthUserGateway {

    /**
     * Finds an account by its normalized username.
     *
     * @param username normalized lookup value
     * @return persisted account or {@code null} when absent
     */
    UserDataBase findByUsername(String username);

    /** Locks the account until the owning transaction completes, before replacing credentials. */
    UserDataBase findByUsernameForUpdate(String username);

    /** Reads the current session epoch without loading credential secrets or the entire account. */
    java.util.Optional<Long> findCredentialEpochById(Long userId);

    /**
     * Checks whether a username is already assigned without loading the full account entity.
     *
     * @param username normalized lookup value
     * @return true when an account uses the username
     */
    boolean existsByUsername(String username);

    /**
     * Persists an account entity and returns the stored representation.
     *
     * @param user account to persist
     * @return persisted account, including generated values
     */
    UserDataBase save(UserDataBase user);
}
