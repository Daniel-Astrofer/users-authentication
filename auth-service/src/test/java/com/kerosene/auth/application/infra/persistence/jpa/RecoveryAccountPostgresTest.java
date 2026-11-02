package com.kerosene.auth.application.infra.persistence.jpa;

import com.kerosene.auth.application.port.out.AuthUserGateway;
import com.kerosene.auth.application.service.crypto.encrypter.AES256;
import com.kerosene.auth.application.service.security.CosignerSecretService;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.security.infra.VaultKeyProvider;
import com.kerosene.security.persistence.StringCryptoConverter;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactoryBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.orm.jpa.*;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Database qualification is restricted to a disposable loopback database, never a Cell database. */
@SpringJUnitConfig(RecoveryAccountPostgresTest.Config.class)
@EnabledIfEnvironmentVariable(named="KEROSENE_RECOVERY_TEST_JDBC",matches="jdbc:postgresql://127[.]0[.]0[.]1:[0-9]+/kerosene_recovery_test")
class RecoveryAccountPostgresTest {
    @Autowired AuthUserGateway users;
    @Autowired UserRepository repository;
    @Autowired JpaTransactionManager manager;
    @Autowired JdbcTemplate jdbc;
    private Long id;
    @BeforeEach
    void fixture() {
        jdbc.execute("TRUNCATE auth.user_backup_codes, auth.users_credentials RESTART IDENTITY CASCADE");
        id=new TransactionTemplate(manager).execute(status->{
            var user=new UserDataBase();user.setUsername("public_fixture");user.setPassphrase("PUBLIC_FIXTURE_HASH");
            user.setBackupCodes(new ArrayList<>(List.of("old-a","old-b","old-c")));
            return repository.saveAndFlush(user).getId();
        });
    }

    @Test
    void realJpaGatewayRequiresATransactionForRecoveryLock() {
        assertThatThrownBy(()->users.findByUsernameForUpdate("public_fixture"))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
    }

    @Test
    void postgresSerializesTheSecondRecoveryAndItReadsTheCommittedReplacement() throws Exception {
        var locked=new CountDownLatch(1);var release=new CountDownLatch(1);
        var pool=Executors.newFixedThreadPool(2);
        try {
            var first=pool.submit(()->new TransactionTemplate(manager).execute(status->{
                var user=users.findByUsernameForUpdate("public_fixture");locked.countDown();
                try { if(!release.await(10,TimeUnit.SECONDS)) throw new IllegalStateException("Fixture lock wait expired."); }
                catch(InterruptedException e) {Thread.currentThread().interrupt();throw new IllegalStateException(e);}
                user.advanceCredentialEpoch();user.setBackupCodes(new ArrayList<>(List.of("new-a","new-b","new-c")));
                users.save(user);return user.getCredentialEpoch();
            }));
            assertThat(locked.await(5,TimeUnit.SECONDS)).isTrue();
            var second=pool.submit(()->new TransactionTemplate(manager).execute(status->{
                var user=users.findByUsernameForUpdate("public_fixture");
                assertThat(user.getBackupCodes()).doesNotContain("old-a","old-b","old-c");
                return user.getCredentialEpoch();
            }));
            boolean databaseLock=false;
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
            while(System.nanoTime()<deadline) {
                databaseLock=jdbc.queryForObject("SELECT count(*) > 0 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",Boolean.class);
                if(databaseLock) break;
                Thread.sleep(20);
            }
            assertThat(databaseLock).as("PostgreSQL confirms an actual lock wait, not only a scheduled thread").isTrue();
            assertThat(second.isDone()).isFalse();release.countDown();
            assertThat(first.get(10,TimeUnit.SECONDS)).isEqualTo(1L);
            assertThat(second.get(10,TimeUnit.SECONDS)).isEqualTo(1L);
        } finally {release.countDown();pool.shutdownNow();}
    }

    @Test
    void anUnrelatedStaleAccountWriteCannotUndoACompletedRecovery() {
        var stale=new TransactionTemplate(manager).execute(status->repository.findById(id).orElseThrow());
        new TransactionTemplate(manager).executeWithoutResult(status->{
            var user=users.findByUsernameForUpdate("public_fixture");user.advanceCredentialEpoch();
            user.setPassphrase("RECOVERED_PUBLIC_FIXTURE_HASH");users.save(user);
        });
        stale.setFailedLoginAttempts(2);
        assertThatThrownBy(()->new TransactionTemplate(manager).executeWithoutResult(status->repository.saveAndFlush(stale)))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        assertThat(users.findCredentialEpochById(id)).contains(1L);
    }

    @Test
    void aFailedRecoveryTransactionDoesNotInvalidateSessions() {
        assertThatThrownBy(()->new TransactionTemplate(manager).executeWithoutResult(status->{
            var user=users.findByUsernameForUpdate("public_fixture");user.advanceCredentialEpoch();users.save(user);
            throw new IllegalStateException("PUBLIC_FIXTURE_ROLLBACK");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(users.findCredentialEpochById(id)).contains(0L);
    }

    @Configuration @EnableTransactionManagement
    static class Config {
        @Bean DataSource dataSource() {
            String url=System.getenv("KEROSENE_RECOVERY_TEST_JDBC");
            if(url==null || !url.matches("jdbc:postgresql://127[.]0[.]0[.]1:[0-9]+/kerosene_recovery_test"))
                throw new IllegalStateException("Disposable recovery database is required.");
            var ds=new DriverManagerDataSource(url,"recovery_test",System.getenv("KEROSENE_RECOVERY_TEST_PASSWORD"));
            new JdbcTemplate(ds).execute("CREATE SCHEMA IF NOT EXISTS auth");return ds;
        }
        @Bean CosignerSecretService cryptoFixture() throws Exception {
            var vault=mock(VaultKeyProvider.class);when(vault.getMasterKey()).thenReturn(new SecretKeySpec(new byte[32],"AES"));
            var service=new CosignerSecretService(new AES256(),vault);new StringCryptoConverter().setCryptoService(service);return service;
        }
        @Bean @DependsOn("cryptoFixture")
        LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource ds) {
            var factory=new LocalContainerEntityManagerFactoryBean();factory.setDataSource(ds);
            factory.setPackagesToScan("com.kerosene.auth.model.entity");factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
            factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto","create-drop","hibernate.default_schema","auth"));return factory;
        }
        @Bean JpaTransactionManager transactionManager(EntityManagerFactory factory) {return new JpaTransactionManager(factory);}
        @Bean JpaRepositoryFactoryBean<UserRepository,UserDataBase,Long> userRepository(EntityManagerFactory factory,DataSource ds) {
            // Exercise the real migration on a generated baseline with the new columns removed.
            new JdbcTemplate(ds).execute("ALTER TABLE auth.users_credentials DROP COLUMN credential_epoch, DROP COLUMN record_version");
            new ResourceDatabasePopulator(new ClassPathResource("db/migration/auth/V17__credential_recovery_epoch.sql")).execute(ds);
            var bean=new JpaRepositoryFactoryBean<UserRepository,UserDataBase,Long>(UserRepository.class);
            bean.setEntityManager(SharedEntityManagerCreator.createSharedEntityManager(factory));return bean;
        }
        @Bean AuthUserGateway userGateway(UserRepository repository) {return new JpaAuthUserGateway(repository);}
        @Bean JdbcTemplate jdbcTemplate(DataSource ds) {return new JdbcTemplate(ds);}
    }
}
