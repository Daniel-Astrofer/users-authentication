package com.kerosene.auth.application.infra.persistence.jpa;

import org.springframework.stereotype.Component;

import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.auth.model.entity.UserDataBase;

/** Adapts the authentication user port to the existing JPA user repository. */
@Component
public class JpaAuthUserGateway implements AuthUserGateway {

    /** Persistence adapter for user entities. */
    private final UserRepository repository;

    /**
     * Creates the gateway with the user persistence repository.
     *
     * @param repository user repository
     */
    public JpaAuthUserGateway(UserRepository repository) {
        this.repository = repository;
    }

    /** Finds a user using the repository's username lookup semantics. */
    @Override
    public UserDataBase findByUsername(String username) {
        return repository.findByUsername(username);
    }

    /** Requires the caller transaction to retain the recovery account lock. */
    @Override
    @org.springframework.transaction.annotation.Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public UserDataBase findByUsernameForUpdate(String username) {
        return repository.findByUsernameForUpdate(username);
    }

    @Override
    public java.util.Optional<Long> findCredentialEpochById(Long userId) {
        return repository.findCredentialEpochById(userId);
    }

    /** Checks whether the username is already stored. */
    @Override
    public boolean existsByUsername(String username) {
        return repository.existsByUsername(username);
    }

    /** Persists the user entity and returns the repository-managed result. */
    @Override
    public UserDataBase save(UserDataBase user) {
        return repository.save(user);
    }
}
