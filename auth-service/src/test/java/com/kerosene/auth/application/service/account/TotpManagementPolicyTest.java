package com.kerosene.auth.application.service.account;

import com.kerosene.auth.AuthExceptions;
import com.kerosene.auth.application.service.cache.contracts.RedisServicer;
import com.kerosene.auth.application.service.user.contract.UserServiceContract;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPKeyGenerate;
import com.kerosene.auth.application.service.validation.totp.contracts.TOTPVerifier;
import com.kerosene.auth.model.entity.UserDataBase;
import com.kerosene.auth.model.enums.AccountSecurityType;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class TotpManagementPolicyTest {
    private final UserServiceContract users = mock(UserServiceContract.class);
    private final RedisServicer redis = mock(RedisServicer.class);
    private final TOTPKeyGenerate generator = mock(TOTPKeyGenerate.class);
    private final TotpManagementService service = new TotpManagementService(
            users, generator, mock(TOTPVerifier.class), redis, mock(BackupCodeService.class));

    @Test
    void activeAuthenticatorCannotBeOverwrittenByNewSetup() {
        UserDataBase user = mock(UserDataBase.class);
        when(users.buscarPorId(42L)).thenReturn(Optional.of(user));
        when(user.getTOTPSecret()).thenReturn("PUBLIC-TOTP-FIXTURE");
        assertThrows(AuthExceptions.StructuredAuthException.class, () -> service.beginSetup(42L));
        verifyNoInteractions(generator, redis);
        verify(users, never()).createUserInDataBase(any());
    }

    @Test
    void mandatoryModesCannotLoseTotpOrRecoveryCodes() {
        for (AccountSecurityType mode : new AccountSecurityType[]{
                AccountSecurityType.SHAMIR, AccountSecurityType.MULTISIG_2FA}) {
            UserDataBase user = mock(UserDataBase.class);
            when(users.buscarPorId(42L)).thenReturn(Optional.of(user));
            when(user.getAccountSecurity()).thenReturn(mode);
            assertThrows(AuthExceptions.StructuredAuthException.class, () -> service.disable(42L));
            verify(user, never()).setTOTPSecret(any());
            verify(user, never()).setBackupCodes(any());
        }
        verify(users, never()).createUserInDataBase(any());
        verifyNoInteractions(redis);
    }

    @Test
    void optionalModeRemovesBothAuthenticatorAndCodes() {
        UserDataBase user = mock(UserDataBase.class);
        when(users.buscarPorId(42L)).thenReturn(Optional.of(user));
        when(user.getAccountSecurity()).thenReturn(AccountSecurityType.STANDARD);
        service.disable(42L);
        verify(user).setTOTPSecret(null);
        verify(user).setBackupCodes(java.util.Collections.emptyList());
        verify(users).createUserInDataBase(user);
        verify(redis).deleteValue("totp:setup:42");
    }
}
