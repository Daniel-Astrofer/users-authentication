package com.kerosene.notification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kerosene.common.financial.notification.FinancialNotificationEventRequest;
import com.kerosene.notification.model.UserNotificationPayload;
import com.kerosene.notification.model.entity.NotificationEntity;
import com.kerosene.notification.repository.NotificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.web.server.ResponseStatusException;

import javax.sql.DataSource;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Runs only against the disposable database created by the notification test script. */
@SpringJUnitConfig(FinancialNotificationInboxPostgresTest.Config.class)
@EnabledIfEnvironmentVariable(named = "KEROSENE_NOTIFICATION_TEST_JDBC",
        matches = "jdbc:postgresql://127[.]0[.]0[.]1:[0-9]+/kerosene_notification_test")
class FinancialNotificationInboxPostgresTest {
    @Autowired FinancialNotificationEventService events;
    @Autowired JdbcTemplate jdbc;
    @Autowired TestPersistence persistence;
    @Autowired CommittedNotifications committed;

    @BeforeEach void clearFixture() {
        persistence.setFail(false);
        committed.count.set(0);
        jdbc.execute("TRUNCATE public.notifications, public.financial_notification_inbox, public.financial_notification_stream RESTART IDENTITY");
    }

    private FinancialNotificationEventRequest event(UUID id, long user, long amount) {
        return new FinancialNotificationEventRequest(id, 1,
                FinancialNotificationEventRequest.Type.PAYMENT_CONFIRMED, user,
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                UUID.fromString("00000000-0000-0000-0000-000000000002"),
                "ONCHAIN", amount, 1, "network-reference", null, null, null,
                Instant.parse("2026-10-09T12:00:00Z"));
    }

    @Test void responseLossReplayDoesNotCreateAnotherNotification() {
        var request = event(UUID.randomUUID(), 42, 1500);
        assertTrue(events.accept(request).accepted());
        assertTrue(events.accept(request).accepted());
        assertEquals(1, count("notifications"));
        assertEquals(1, count("financial_notification_inbox"));
        assertEquals(1, committed.count.get());
        assertEquals(request.occurredAt().toString(), jdbc.queryForObject(
                "SELECT metadata_json::json->>'occurredAt' FROM public.notifications", String.class));
    }

    @Test void concurrentDeliveryPublishesOnlyTheCommittedWinner() throws Exception {
        var request = event(UUID.randomUUID(), 42, 1500);
        var start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var first = pool.submit(() -> { start.await(); return events.accept(request); });
            var second = pool.submit(() -> { start.await(); return events.accept(request); });
            start.countDown();
            assertTrue(first.get(10, TimeUnit.SECONDS).accepted());
            assertTrue(second.get(10, TimeUnit.SECONDS).accepted());
        }
        assertEquals(1, count("notifications"));
        assertEquals(1, committed.count.get());
    }

    @Test void reusedIdentityWithDifferentRecipientOrAmountIsRejected() {
        var id = UUID.randomUUID();
        events.accept(event(id, 42, 1500));
        assertEquals(409, assertThrows(ResponseStatusException.class,
                () -> events.accept(event(id, 43, 1500))).getStatusCode().value());
        assertEquals(409, assertThrows(ResponseStatusException.class,
                () -> events.accept(event(id, 42, 1501))).getStatusCode().value());
        assertEquals(1, count("notifications"));
        assertEquals(1, committed.count.get());
    }

    @Test void failureAfterNotificationInsertRollsBackInboxAndNotification() {
        var request = event(UUID.randomUUID(), 42, 1500);
        persistence.setFail(true);
        assertThrows(IllegalStateException.class, () -> events.accept(request));
        assertEquals(0, count("notifications"));
        assertEquals(0, count("financial_notification_inbox"));
        assertEquals(0, committed.count.get());
        persistence.setFail(false);
        assertTrue(events.accept(request).accepted());
        assertEquals(1, count("notifications"));
        assertEquals(1, committed.count.get());
    }

    @Test void lateProcessingIsStoredWithoutRegressingTheLiveNotification() {
        var confirmed = event(UUID.randomUUID(), 42, 1500);
        var terminal = new FinancialNotificationEventRequest(confirmed.eventId(), 1, confirmed.type(),
                42L, confirmed.transactionId(), confirmed.walletId(), "ONCHAIN", 1500, 1,
                null, null, null, null, confirmed.occurredAt(), 2);
        var older = new FinancialNotificationEventRequest(UUID.randomUUID(), 1,
                FinancialNotificationEventRequest.Type.PAYMENT_PROCESSING, 42L,
                confirmed.transactionId(), confirmed.walletId(), "ONCHAIN", 1500, 0,
                null, null, null, null, confirmed.occurredAt().minusSeconds(60), 1);
        events.accept(terminal);
        events.accept(older);
        assertEquals(2, count("notifications"));
        assertEquals(1, committed.count.get());
        assertEquals(2L, jdbc.queryForObject("SELECT last_sequence FROM public.financial_notification_stream", Long.class));
    }

    private int count(String fixtureTable) {
        return jdbc.queryForObject("SELECT count(*) FROM public." + fixtureTable, Integer.class);
    }

    static class CommittedNotifications {
        final AtomicInteger count = new AtomicInteger();
        @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
        public void committed(NotificationPersistedEvent event) { count.incrementAndGet(); }
    }

    static class TestPersistence extends NotificationPersistenceService {
        volatile boolean fail;
        TestPersistence(NotificationRepository repository, ApplicationEventPublisher publisher) { super(repository, publisher); }
        public void setFail(boolean value) { fail = value; }
        @Override @Transactional public NotificationEntity persist(Long user, UserNotificationPayload payload, boolean dispatch) {
            var result = super.persist(user, payload, dispatch);
            if (fail) throw new IllegalStateException("Injected failure before commit.");
            return result;
        }
    }

    @Configuration @EnableTransactionManagement
    @EnableJpaRepositories(basePackageClasses = NotificationRepository.class)
    static class Config {
        @Bean DataSource dataSource() {
            String url = System.getenv("KEROSENE_NOTIFICATION_TEST_JDBC");
            if (url == null || !url.matches("jdbc:postgresql://127[.]0[.]0[.]1:[0-9]+/kerosene_notification_test"))
                throw new IllegalStateException("Disposable test database is required.");
            var ds = new DriverManagerDataSource(url,
                    "notification_test", System.getenv("KEROSENE_NOTIFICATION_TEST_PASSWORD"));
            new JdbcTemplate(ds).execute("DROP TABLE IF EXISTS public.financial_notification_inbox, public.financial_notification_stream");
            new ResourceDatabasePopulator(new ClassPathResource(
                    "db/migration/auth/V16__financial_notification_inbox.sql")).execute(ds);
            return ds;
        }
        @Bean LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource ds) {
            var factory = new LocalContainerEntityManagerFactoryBean();
            factory.setDataSource(ds);
            factory.setPackagesToScan("com.kerosene.notification.model.entity");
            factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
            factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "create-drop"));
            return factory;
        }
        @Bean JpaTransactionManager transactionManager(EntityManagerFactory factory) { return new JpaTransactionManager(factory); }
        @Bean JdbcTemplate jdbcTemplate(DataSource ds) { return new JdbcTemplate(ds); }
        @Bean ObjectMapper objectMapper() { return new ObjectMapper().registerModule(new JavaTimeModule()); }
        @Bean TestPersistence persistence(NotificationRepository repository, ApplicationEventPublisher publisher) {
            return new TestPersistence(repository, publisher);
        }
        @Bean FinancialNotificationEventService events(JdbcTemplate jdbc, ObjectMapper mapper, TestPersistence persistence) {
            return new FinancialNotificationEventService(jdbc, mapper, persistence);
        }
        @Bean CommittedNotifications committedNotifications() { return new CommittedNotifications(); }
    }
}
