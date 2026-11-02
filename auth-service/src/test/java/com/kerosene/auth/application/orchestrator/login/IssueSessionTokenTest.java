package com.kerosene.auth.application.orchestrator.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.notification.model.UserNotificationPayload;
import com.kerosene.notification.service.NotificationService;

class IssueSessionTokenTest {

    @Test
    void issueShouldGenerateJwtAndNotifyUser() {
        JwtServicer jwtService = mock(JwtServicer.class);
        NotificationService notificationService = mock(NotificationService.class);
        IssueSessionToken issueSessionToken = new IssueSessionToken(jwtService, notificationService);

        UserDataBase user = new UserDataBase();
        ReflectionTestUtils.setField(user, "id", 7L);
        when(jwtService.generateTokenAtCredentialEpoch(eq(7L), anyCollection(), eq(0L))).thenReturn("jwt-token");

        String result = issueSessionToken.issue(user);

        assertEquals("7 jwt-token", result);
        ArgumentCaptor<UserNotificationPayload> payloadCaptor =
                ArgumentCaptor.forClass(UserNotificationPayload.class);
        verify(notificationService).notifyUser(eq(7L), payloadCaptor.capture());
        UserNotificationPayload payload = payloadCaptor.getValue();
        assertEquals("security_login_detected", payload.kind());
        assertEquals("warning", payload.severity());
        assertEquals("Novo acesso detectado", payload.title());
        assertEquals(
                "Identificamos um novo acesso à sua conta Kerosene. Se não reconhece esta atividade, revise suas sessões ativas imediatamente.",
                payload.body());
        assertEquals("/settings", payload.deeplink());
        assertEquals("user", payload.entityType());
        assertEquals("7", payload.entityId());
    }
}
