package com.kerosene.auth.application.infra.persistence.jpa;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.kerosene.auth.model.entity.AdminKeyEntity;
import com.kerosene.auth.model.enums.AdminKeyStatus;

/** Queries administrative signing/approval keys by user and lifecycle state. */
@Repository
public interface AdminKeyRepository extends JpaRepository<AdminKeyEntity, UUID> {
    /**
     * Finds the most recently created key for one account and lifecycle state.
     *
     * @param userId account identifier
     * @param status key lifecycle state to select
     * @return newest matching key, or empty when no enrollment matches
     */
    Optional<AdminKeyEntity> findFirstByUserIdAndStatusOrderByCreatedAtDesc(Long userId, AdminKeyStatus status);

    /**
     * Lists all key enrollments for one account in the requested lifecycle state.
     *
     * @param userId account identifier
     * @param status key lifecycle state to select
     * @return all matching enrollments
     */
    List<AdminKeyEntity> findByUserIdAndStatus(Long userId, AdminKeyStatus status);
}
