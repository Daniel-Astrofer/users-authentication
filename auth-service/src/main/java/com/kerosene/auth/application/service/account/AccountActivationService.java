package com.kerosene.auth.application.service.account;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.dto.AccountActivationStatusDTO;
import com.kerosene.auth.model.entity.UserDataBase;

import java.time.LocalDateTime;

/** Provides activation status and enforces whether the account may receive inbound funds. */
@Service
public class AccountActivationService {

    /** Account persistence boundary used for lookup and activation updates. */
    private final UserServiceContract userService;

    /**
     * Creates the activation service.
     *
     * @param userService account lookup and persistence boundary used to read activation fields
     */
    public AccountActivationService(UserServiceContract userService) {
        this.userService = userService;
    }

    /**
     * Loads account state and projects it into the activation response.
     *
     * @param userId persisted account identifier
     * @return activation status derived from the persisted active flag and timestamp
     * @throws AuthExceptions.InvalidCredentials when the account cannot be found
     */
    public AccountActivationStatusDTO getStatus(Long userId) {
        UserDataBase user = requireUser(userId);
        return AccountActivationStatusDTO.from(new ActivationUserView(user));
    }

    /**
     * Returns current activation state; this implementation does not create a payment link.
     *
     * @param userId persisted account identifier
     * @return activation status with payment-link fields unset
     * @throws AuthExceptions.InvalidCredentials when the account cannot be found
     */
    @Transactional
    public AccountActivationStatusDTO createOrReuseLink(Long userId) {
        UserDataBase user = requireUser(userId);
        return AccountActivationStatusDTO.from(new ActivationUserView(user));
    }

    /**
     * Rejects legacy external-link confirmation because initial deposits must use the platform flow.
     *
     * @param userId account identifier (unused by the disabled flow)
     * @param linkId legacy activation link identifier
     * @param txid legacy transaction identifier
     * @param fromAddress legacy source address
     * @return never returns; the operation is rejected
     * @throws AuthExceptions.AuthValidationException because external-link activation is disabled
     */
    @Transactional
    public AccountActivationStatusDTO confirm(Long userId, String linkId, String txid, String fromAddress) {
        throw new AuthExceptions.AuthValidationException(
                "O deposito inicial agora deve ser feito dentro da plataforma, nao por link de ativacao.");
    }

    /**
     * Marks the account active once and records its activation timestamp. Existing active accounts
     * are returned without changing their original activation time.
     *
     * @param userId persisted account identifier
     * @return active persisted account
     * @throws AuthExceptions.InvalidCredentials when the account cannot be found
     */
    @Transactional
    public UserDataBase activateUser(Long userId) {
        UserDataBase user = requireUser(userId);
        if (Boolean.TRUE.equals(user.getIsActive())) {
            return user;
        }
        user.setIsActive(true);
        user.setActivatedAt(LocalDateTime.now());
        return userService.createUserInDataBase(user);
    }

    /**
     * Ensures inbound operations are enabled for the account found by ID.
     *
     * @param userId persisted account identifier
     * @throws AuthExceptions.InvalidCredentials when the account cannot be found
     * @throws AuthExceptions.InboundReceivingBlockedException when the account is inactive
     */
    public void assertInboundEnabled(Long userId) {
        assertInboundEnabled(requireUser(userId));
    }

    /**
     * Rejects inbound operations unless the supplied account is explicitly active.
     *
     * @param user account entity whose active flag gates inbound funding
     * @throws AuthExceptions.InboundReceivingBlockedException when the account is inactive
     */
    public void assertInboundEnabled(UserDataBase user) {
        if (!Boolean.TRUE.equals(user.getIsActive())) {
            throw new AuthExceptions.InboundReceivingBlockedException(
                    AccountActivationStatusDTO.INBOUND_BLOCKED_MESSAGE);
        }
    }

    /**
     * Loads an account or rejects the request as unauthenticated or based on stale identity.
     *
     * @param userId account identifier to resolve
     * @return persisted account entity
     * @throws AuthExceptions.InvalidCredentials when the account cannot be found
     */
    private UserDataBase requireUser(Long userId) {
        return userService.buscarPorId(userId)
                .orElseThrow(() -> new AuthExceptions.InvalidCredentials("Authenticated user not found."));
    }

    /**
     * Minimal adapter exposing activation fields from the persisted user entity.
     *
     * @param user source entity providing the activation values
     */
    private record ActivationUserView(UserDataBase user) implements AccountActivationStatusDTO.UserDataBaseView {
        /**
         * Reports active only for an explicit true value; null is treated as inactive.
         *
         * @return account activity state
         */
        @Override
        public boolean isActive() {
            return Boolean.TRUE.equals(user.getIsActive());
        }

        /**
         * Returns the persisted activation timestamp without synthesizing a value.
         *
         * @return activation time, or {@code null} when not active
         */
        @Override
        public LocalDateTime activatedAt() {
            return user.getActivatedAt();
        }
    }
}
