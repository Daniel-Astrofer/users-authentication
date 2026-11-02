package com.kerosene.notification.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.notification.model.UserNotificationPayload;
import com.kerosene.notification.model.entity.NotificationEntity;
import com.kerosene.notification.repository.NotificationRepository;

@Service
public class NotificationPersistenceService {

    private final NotificationRepository repository;
    private final ApplicationEventPublisher eventPublisher;

    public NotificationPersistenceService(
            NotificationRepository repository,
            ApplicationEventPublisher eventPublisher) {
        this.repository = repository;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public NotificationEntity persist(Long userId, UserNotificationPayload payload) {
        return persist(userId, payload, true);
    }

    @Transactional
    public NotificationEntity persist(Long userId, UserNotificationPayload payload, boolean dispatch) {
        NotificationEntity entity = new NotificationEntity();
        entity.setUserId(userId);
        entity.setKind(payload.kind());
        entity.setSeverity(payload.severity());
        entity.setTitle(payload.title());
        entity.setBody(payload.body());
        entity.setDeeplink(payload.deeplink());
        entity.setEntityType(payload.entityType());
        entity.setEntityId(payload.entityId());
        entity.setMetadata(payload.metadata());
        entity.setRead(false);
        entity.setCreatedAt(resolveCreatedAtUtc(payload));

        NotificationEntity saved = repository.save(entity);

        Map<String, Object> payloadMap = new LinkedHashMap<>(payload.toMap());
        payloadMap.put("id", saved.getId());
        // Keep live push on the same Instant that was persisted.
        Instant createdAt = saved.getCreatedAtUtc();
        if (createdAt != null) {
            String zulu = createdAt.toString();
            payloadMap.put("createdAt", zulu);
            payloadMap.put("timestamp", zulu);
        }

        if (dispatch) eventPublisher.publishEvent(new NotificationPersistedEvent(userId, payloadMap));
        return saved;
    }

    private static LocalDateTime resolveCreatedAtUtc(UserNotificationPayload payload) {
        String raw = payload.createdAt() != null ? payload.createdAt() : payload.timestamp();
        if (raw != null && !raw.isBlank()) {
            try {
                return LocalDateTime.ofInstant(Instant.parse(raw), ZoneOffset.UTC);
            } catch (Exception ignored) {
                // fall through to clock
            }
        }
        return LocalDateTime.now(ZoneOffset.UTC);
    }
}
