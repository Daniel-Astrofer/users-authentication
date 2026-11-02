package com.kerosene.auth.application.infra.persistence.jpa;

import jakarta.persistence.LockModeType;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.kerosene.auth.model.entity.AdminAccessAttemptEntity;
import com.kerosene.auth.model.enums.AdminAccessAttemptStatus;

/** Persistence queries for admin access attempts, including locking of polling transitions. */
@Repository
public interface AdminAccessAttemptRepository extends JpaRepository<AdminAccessAttemptEntity, UUID> {
    /**
     * Loads an access attempt under a pessimistic write lock before polling can transition it.
     *
     * @param id access-attempt identifier
     * @return locked attempt when present
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select attempt from AdminAccessAttemptEntity attempt where attempt.id = :id")
    Optional<AdminAccessAttemptEntity> findForPollingById(@Param("id") UUID id);

    /**
     * Finds an attempt only when it belongs to the supplied user, preventing cross-account lookup.
     *
     * @param id access-attempt identifier
     * @param userId owning account identifier
     * @return matching attempt, or empty when absent or owned by another account
     */
    Optional<AdminAccessAttemptEntity> findByIdAndUserId(UUID id, Long userId);

    /**
     * Lists attempts matching one user's state whose expiry is strictly after the supplied time.
     * Results are ordered newest request first for approval-device polling.
     *
     * @param userId owning account identifier
     * @param status lifecycle state to select
     * @param now comparison time; rows expiring exactly at this instant are excluded
     * @return matching attempts ordered by request time descending
     */
    List<AdminAccessAttemptEntity> findByUserIdAndStatusAndExpiresAtAfterOrderByRequestedAtDesc(
            Long userId,
            AdminAccessAttemptStatus status,
            LocalDateTime now);
}
