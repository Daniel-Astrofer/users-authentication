package com.kerosene.auth.application.infra.persistence.jpa;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.kerosene.auth.model.entity.AdminAccessDeviceEntity;

/** Persistence queries for administrator device enrollment and last-access ordering. */
@Repository
public interface AdminAccessDeviceRepository extends JpaRepository<AdminAccessDeviceEntity, UUID> {
    /**
     * Finds an enrolled device scoped to its owning account.
     *
     * @param userId account identifier
     * @param deviceId stable enrolled-device identifier
     * @return matching device, or empty when not enrolled for that user
     */
    Optional<AdminAccessDeviceEntity> findByUserIdAndDeviceId(Long userId, String deviceId);

    /**
     * Lists one account's registered devices ordered by descending last-access time.
     *
     * @param userId account identifier
     * @return devices for that account, newest access first; devices with null timestamps follow database ordering
     */
    List<AdminAccessDeviceEntity> findByUserIdOrderByLastAccessAtDesc(Long userId);
}
