package com.kerosene.auth.application.service.account;

import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import com.kerosene.common.exception.ErrorCodes;
import com.kerosene.auth.model.enums.AccountSecurityType;
import java.util.Map;
import org.springframework.transaction.annotation.Transactional;
import com.kerosene.auth.AuthConstants;
import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPKeyGenerate;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.dto.BackupCodesStatusDTO;
import com.kerosene.auth.dto.TotpSetupResponseDTO;
import com.kerosene.auth.model.entity.UserDataBase;

/** Manages TOTP enrollment using expiring setup secrets and backup-code rotation. */
@Service
public class TotpManagementService {

    /** TTL for an unconfirmed TOTP secret held in temporary storage. */
    private static final long SETUP_TTL_SECONDS = 600L;

    /** Account lookup and persistence boundary. */
    private final UserServiceContract userService;
    /** Generates new random TOTP secrets. */
    private final TOTPKeyGenerate totpKeyGenerate;
    /** Verifies enrollment codes against temporary secrets. */
    private final TOTPVerifier totpVerifier;
    /** Temporary storage for the pending enrollment secret. */
    private final RedisServicer redisService;
    /** Replaces backup codes after enrollment completes. */
    private final BackupCodeService backupCodeService;

    /** Creates the TOTP management service. */
    /** @param userService account lookup and persistence */
    /** @param totpKeyGenerate secret generator */
    /** @param totpVerifier enrollment verifier */
    /** @param redisService temporary secret storage */
    /** @param backupCodeService backup-code rotation service */
    public TotpManagementService(
            UserServiceContract userService,
            TOTPKeyGenerate totpKeyGenerate,
            TOTPVerifier totpVerifier,
            RedisServicer redisService,
            BackupCodeService backupCodeService) {
        this.userService = userService;
        this.totpKeyGenerate = totpKeyGenerate;
        this.totpVerifier = totpVerifier;
        this.redisService = redisService;
        this.backupCodeService = backupCodeService;
    }

    /** Generates a temporary secret, stores it for ten minutes, and returns an authenticator URI. */
    /** @param userId account identifier */
    /** @return enrollment URI and secret for authenticator setup */
    public TotpSetupResponseDTO beginSetup(Long userId) {
        UserDataBase user = requireUser(userId);
        if (user.getTOTPSecret() != null && !user.getTOTPSecret().isBlank()) {
            throw new AuthExceptions.StructuredAuthException(
                    "O autenticador já está ativo. Revise a configuração antes de alterar a proteção.",
                    HttpStatus.CONFLICT, ErrorCodes.AUTH_TRANSACTIONAL_AUTH_REQUIRED,
                    Map.of("action", "TOTP_ALREADY_ENABLED"));
        }
        String secret = totpKeyGenerate.keyGenerator();
        redisService.setValue(tempSetupKey(userId), secret, SETUP_TTL_SECONDS);
        String otpUri = String.format(
                AuthConstants.TOTP_URI_FORMAT,
                AuthConstants.APP_NAME,
                user.getUsername(),
                secret,
                AuthConstants.APP_NAME);
        return new TotpSetupResponseDTO(otpUri, secret);
    }

    /** Verifies the temporary setup code, persists the secret, clears temporary state, and rotates backup codes. */
    /** @param userId account identifier */
    /** @param code submitted authenticator code */
    /** @return backup-code status and newly issued codes */
    /** @throws AuthExceptions.TotpTimeExceededException when the setup TTL has elapsed */
    /** @throws AuthExceptions.IncorrectTotpException when the code is missing */
    @Transactional
    public BackupCodesStatusDTO verifySetup(Long userId, String code) {
        String secret = redisService.getValue(tempSetupKey(userId));
        if (secret == null || secret.isBlank()) {
            throw new AuthExceptions.TotpTimeExceededException("TOTP setup session expired. Start setup again.");
        }
        if (code == null || code.isBlank()) {
            throw new AuthExceptions.IncorrectTotpException("TOTP code required.");
        }

        totpVerifier.totpVerify(secret, code);
        UserDataBase user = requireUser(userId);
        user.setTOTPSecret(secret);
        userService.createUserInDataBase(user);
        redisService.deleteValue(tempSetupKey(userId));
        return backupCodeService.regenerate(userId);
    }

    /** Clears the persisted TOTP secret and backup codes, and removes any pending setup secret. */
    /** @param userId account identifier */
    @Transactional
    public void disable(Long userId) {
        UserDataBase user = requireUser(userId);
        if (user.getAccountSecurity() == AccountSecurityType.SHAMIR ||
                user.getAccountSecurity() == AccountSecurityType.MULTISIG_2FA) {
            throw new AuthExceptions.StructuredAuthException(
                    "Este perfil de segurança exige o autenticador.",
                    HttpStatus.CONFLICT, ErrorCodes.AUTH_TRANSACTIONAL_AUTH_REQUIRED,
                    Map.of("required", "TOTP", "action", "CHANGE_SECURITY_PROFILE"));
        }
        user.setTOTPSecret(null);
        user.setBackupCodes(java.util.Collections.emptyList());
        userService.createUserInDataBase(user);
        redisService.deleteValue(tempSetupKey(userId));
    }

    /** Loads the account or fails because the authenticated account is unavailable. */
    /** @param userId account identifier */
    /** @return persisted account */
    /** @throws IllegalStateException when account lookup fails */
    private UserDataBase requireUser(Long userId) {
        return userService.buscarPorId(userId)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found."));
    }

    /** Builds the Redis key that scopes a pending setup secret to the account. */
    /** @param userId account identifier */
    /** @return namespaced temporary key */
    private String tempSetupKey(Long userId) {
        return "totp:setup:" + userId;
    }
}
