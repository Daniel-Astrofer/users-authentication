package com.kerosene.auth.application.orchestrator.login;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import com.kerosene.auth.application.service.validation.jwt.contracts.JwtServicer;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.notification.l10n.NotificationMessageKey;
import com.kerosene.notification.l10n.NotificationMessages;
import com.kerosene.notification.model.NotificationKind;
import com.kerosene.notification.model.NotificationSeverity;
import com.kerosene.notification.service.NotificationService;

import java.util.List;
import java.util.Map;

/** Issues the authenticated session token and emits a best-effort security notification. */
@Component
public class IssueSessionToken {

    /** Logger used when optional login notification delivery fails. */
    private static final Logger log = LoggerFactory.getLogger(IssueSessionToken.class);

    /** JWT generator used after the user has completed the required factors. */
    private final JwtServicer jwtService;
    /** Notification adapter for security events; delivery does not gate authentication. */
    private final NotificationService notificationService;

    /**
     * Creates the token issuer; notification injection is lazy to avoid a service dependency cycle.
     *
     * @param jwtService service that signs session tokens
     * @param notificationService notification service for login alerts
     */
    public IssueSessionToken(JwtServicer jwtService,
            @Lazy
            NotificationService notificationService) {
        this.jwtService = jwtService;
        this.notificationService = notificationService;
    }

    /**
     * Sends a best-effort login alert, then returns the legacy user-ID and JWT response string.
     *
     * @param user authenticated user whose identifier and role become token claims
     * @return user ID, one space, and the signed JWT
     */
    public String issue(UserDataBase user) {
        String token = jwtService.generateTokenAtCredentialEpoch(user.getId(), List.of(user.getRole().name()), user.getCredentialEpoch());
        if (token == null || token.isBlank()) throw new IllegalStateException("Authenticated session token was not issued.");
        notifyLogin(user.getId());
        return user.getId() + " " + token;
    }

    /** Sends a warning notification for the login without failing token issuance on delivery errors. */
    /** @param userId identifier of the account that logged in */
    private void notifyLogin(Long userId) {
        try {
            notificationService.notifyUser(
                    userId,
                    NotificationMessages.payload(
                            NotificationKind.SECURITY_LOGIN_DETECTED,
                            NotificationSeverity.WARNING,
                            NotificationMessageKey.SECURITY_LOGIN_DETECTED,
                            "/settings",
                            "user",
                            String.valueOf(userId),
                            Map.of("scope", "session")));
        } catch (Exception e) {
            log.warn("Falha ao enviar notificação de login para usuário {}", userId, e);
        }
    }
}
