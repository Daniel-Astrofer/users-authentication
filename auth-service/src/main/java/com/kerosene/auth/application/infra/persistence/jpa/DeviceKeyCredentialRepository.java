package com.kerosene.auth.application.infra.persistence.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.kerosene.auth.model.entity.DeviceKeyCredential;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Persistence queries and monotonic-counter updates for registered device-key credentials. */
@Repository
public interface DeviceKeyCredentialRepository extends JpaRepository<DeviceKeyCredential, UUID> {

    /**
     * Finds a credential by its protocol credential identifier without owner scoping.
     *
     * @param credentialId globally unique credential identifier supplied by the client
     * @return matching credential, or empty when no row exists
     */
    Optional<DeviceKeyCredential> findByCredentialId(String credentialId);

    /**
     * Finds a credential only when it is associated with the specified account.
     *
     * @param credentialId protocol credential identifier
     * @param userId owning account identifier
     * @return matching account-owned credential, or empty on missing/foreign ownership
     */
    Optional<DeviceKeyCredential> findByCredentialIdAndUserId(String credentialId, Long userId);

    /**
     * Lists every device-key credential row owned by an account, including revoked entries.
     *
     * @param userId owning account identifier
     * @return credential rows for the account
     */
    List<DeviceKeyCredential> findByUserId(Long userId);

    /**
     * Checks whether an account has any active credential, treating null legacy status as ACTIVE.
     *
     * @param userId owning account identifier
     * @return true when at least one active row exists
     */
    @Query("""
            select count(d) > 0 from DeviceKeyCredential d
             where d.user.id = :userId
               and upper(coalesce(d.status, 'ACTIVE')) = 'ACTIVE'
            """)
    boolean existsActiveByUserId(@Param("userId") Long userId);

    /**
     * Atomically advances an active credential's authenticator counter and last-used time.
     * The strict old-counter predicate rejects replayed or non-increasing assertions.
     *
     * @param credentialId WebAuthn credential ID
     * @param userId owning user ID
     * @param newCounter counter reported by the verified authenticator assertion
     * @param lastUsedAt verification time to persist
     * @return number of rows updated; zero means ownership/state/counter preconditions failed
     */
    @Modifying
    @Query("""
            update DeviceKeyCredential d
               set d.counter = :newCounter,
                   d.lastUsedAt = :lastUsedAt
             where d.credentialId = :credentialId
               and d.user.id = :userId
               and upper(d.status) = 'ACTIVE'
               and d.counter < :newCounter
            """)
    int advanceCounter(
            @Param("credentialId") String credentialId,
            @Param("userId") Long userId,
            @Param("newCounter") long newCounter,
            @Param("lastUsedAt") LocalDateTime lastUsedAt);

    /**
     * Loads active credentials for one installation and fetches the owning user in the same query.
     * Null legacy status is treated as ACTIVE for compatibility.
     *
     * @param deviceInstallId installation identifier being checked for account binding
     * @return active credentials with their owner relation loaded
     */
    @org.springframework.data.jpa.repository.EntityGraph(attributePaths = "user")
    @Query("""
            select d from DeviceKeyCredential d
             where d.deviceInstallId = :deviceInstallId
               and upper(coalesce(d.status, 'ACTIVE')) = 'ACTIVE'
            """)
    List<DeviceKeyCredential> findActiveByDeviceInstallId(@Param("deviceInstallId") String deviceInstallId);

    /**
     * Deletes all credential rows associated with one installation identifier across owners.
     *
     * @param deviceInstallId installation identifier whose credential rows are removed
     * @return number of deleted rows
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from DeviceKeyCredential d where d.deviceInstallId = :deviceInstallId")
    int deleteByDeviceInstallId(@Param("deviceInstallId") String deviceInstallId);

    /**
     * Deletes credentials for one installation only within the specified account's ownership scope.
     *
     * @param userId owning account identifier
     * @param deviceInstallId installation identifier whose account-owned rows are removed
     * @return number of deleted rows
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            delete from DeviceKeyCredential d
             where d.user.id = :userId
               and d.deviceInstallId = :deviceInstallId
            """)
    int deleteByUserIdAndDeviceInstallId(
            @Param("userId") Long userId,
            @Param("deviceInstallId") String deviceInstallId);
}
