package com.kerosene.auth.application.usecase.passkey;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.application.infra.persistence.jpa.UserRepository;
import com.kerosene.auth.application.service.passkey.PasskeyInventoryService;
import com.kerosene.auth.dto.PasskeyInventoryDTO;
import com.kerosene.auth.model.entity.UserDataBase;

/** Retrieves the public passkey inventory for an existing account. */
@Component
public class GetPasskeyInventoryUseCase {

    /** Resolves the account whose inventory is requested. */
    private final UserRepository userRepository;
    /** Projects stored credential state into the passkey inventory DTO. */
    private final PasskeyInventoryService passkeyInventoryService;

    /**
     * Creates the inventory query use case.
     * @param userRepository account lookup repository
     * @param passkeyInventoryService inventory projection service
     */
    public GetPasskeyInventoryUseCase(
            UserRepository userRepository,
            PasskeyInventoryService passkeyInventoryService) {
        this.userRepository = userRepository;
        this.passkeyInventoryService = passkeyInventoryService;
    }

    /**
     * Returns the user's projected inventory, or a typed not-found outcome.
     * @param userId account identifier
     * @return inventory result
     */
    @Transactional(readOnly = true)
    public Result execute(Long userId) {
        UserDataBase user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Result.userNotFound();
        }

        return Result.found(passkeyInventoryService.inventoryFor(user));
    }

    /**
     * Result of querying a passkey inventory.
     * @param status indicates whether the account was found
     * @param message optional public error message for a missing account
     * @param inventory projected passkey metadata when found
     */
    public record Result(Status status, String message, PasskeyInventoryDTO inventory) {

        /**
         * Builds a not-found result.
         * @return missing-user result
         */
        private static Result userNotFound() {
            return new Result(Status.USER_NOT_FOUND, "User not found", null);
        }

        /**
         * Builds a result containing the current inventory projection.
         * @param inventory projected account inventory
         * @return successful result
         */
        private static Result found(PasskeyInventoryDTO inventory) {
            return new Result(Status.FOUND, null, inventory);
        }
    }

    /** Outcomes of querying passkey inventory. */
    public enum Status {
        /** Account exists and its inventory is included in the result. */
        FOUND,
        /** No account matched the requested user identifier. */
        USER_NOT_FOUND
    }
}
