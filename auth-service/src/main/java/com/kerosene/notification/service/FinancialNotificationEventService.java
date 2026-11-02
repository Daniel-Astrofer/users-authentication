package com.kerosene.notification.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kerosene.common.financial.notification.FinancialNotificationEventRequest;
import com.kerosene.common.financial.notification.FinancialNotificationReceipt;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/** Inbox insert and user notification participate in the same database transaction. */
@Service
public class FinancialNotificationEventService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final NotificationPersistenceService persistence;

    public FinancialNotificationEventService(JdbcTemplate jdbc, ObjectMapper mapper,
                                             NotificationPersistenceService persistence) {
        this.jdbc = jdbc;
        this.mapper = mapper.copy()
                .configure(com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS);
        this.persistence = persistence;
    }

    @Transactional
    public FinancialNotificationReceipt accept(FinancialNotificationEventRequest event) {
        Objects.requireNonNull(event, "event is required");
        String hash = fingerprint(event);
        // PostgreSQL waits for a competing insert to commit, without aborting this
        // transaction on a duplicate. A response lost after commit is a safe replay.
        int inserted = jdbc.update("""
                INSERT INTO public.financial_notification_inbox
                    (event_id, user_id, transaction_id, request_hash)
                VALUES (?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING
                """, event.eventId(), event.userId(), event.transactionId(), hash);
        if (inserted == 0) {
            String existing = jdbc.queryForObject("""
                    SELECT request_hash FROM public.financial_notification_inbox WHERE event_id = ?
                    """, String.class, event.eventId());
            if (!hash.equals(existing)) throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Financial event identity was reused with different content.");
        } else if (inserted == 1) {
            int advanced = jdbc.update("""
                    INSERT INTO public.financial_notification_stream
                      (user_id, transaction_id, last_sequence, last_occurred_at) VALUES (?, ?, ?, ?)
                    ON CONFLICT (user_id, transaction_id) DO UPDATE
                      SET last_sequence = EXCLUDED.last_sequence, last_occurred_at = EXCLUDED.last_occurred_at
                    WHERE (EXCLUDED.last_sequence > 0 AND EXCLUDED.last_sequence > financial_notification_stream.last_sequence)
                       OR (EXCLUDED.last_sequence = 0 AND financial_notification_stream.last_sequence = 0
                           AND EXCLUDED.last_occurred_at >= financial_notification_stream.last_occurred_at)
                    """, event.userId(), event.transactionId(), event.eventSequence(),
                    java.sql.Timestamp.from(event.occurredAt()));
            // Late historical events remain in the inbox, but cannot replace a
            // newer live notification with a stale "processing" announcement.
            persistence.persist(event.userId(), FinancialNotificationPayloads.from(event), advanced == 1);
        } else {
            throw new IllegalStateException("Unexpected financial inbox insert result.");
        }
        return new FinancialNotificationReceipt(event.eventId(), true);
    }

    private String fingerprint(FinancialNotificationEventRequest event) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(mapper.writeValueAsBytes(event)));
        } catch (JsonProcessingException | NoSuchAlgorithmException failure) {
            throw new IllegalStateException("Could not encode financial event identity.", failure);
        }
    }
}
