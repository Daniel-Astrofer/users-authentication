package com.kerosene.auth.application.orchestrator.signup.infra;

import java.util.List;

import org.springframework.stereotype.Component;

import com.kerosene.auth.application.orchestrator.signup.port.PasskeyGateway;
import com.kerosene.auth.application.port.out.AuthPasskeyGateway;
import com.kerosene.auth.model.entity.PasskeyCredential;

/** Adapts the application passkey output port to signup's narrower persistence gateway. */
@Component
public class AuthPasskeyGatewayAdapter implements PasskeyGateway {

    /** Outbound authentication port that performs passkey persistence and lookup. */
    private final AuthPasskeyGateway delegate;

    /**
     * Creates the gateway adapter.
     *
     * @param delegate application output port that owns passkey persistence
     */
    public AuthPasskeyGatewayAdapter(AuthPasskeyGateway delegate) {
        this.delegate = delegate;
    }

    /**
     * Delegates credential persistence to the application output port.
     *
     * @param credential credential to persist
     * @return persisted credential
     */
    @Override
    public PasskeyCredential save(PasskeyCredential credential) {
        return delegate.save(credential);
    }

    /**
     * Delegates owner-scoped credential lookup to the application output port.
     *
     * @param userId account identifier
     * @return credentials belonging to the account
     */
    @Override
    public List<PasskeyCredential> findByUserId(Long userId) {
        return delegate.findByUserId(userId);
    }
}
