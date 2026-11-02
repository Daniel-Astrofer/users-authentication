package com.kerosene.auth.application.service.identityaccess;

import org.springframework.stereotype.Component;
import com.kerosene.auth.model.entity.UserDataBase;

/** Fail-closed binding for the retired platform co-signer; Vault Mesh signs custody operations. */
@Component
public class UnavailablePlatformTransactionSigner implements PlatformTransactionSignerPort {

    /** Always reports unavailable so advanced outbound authorization fails closed in every profile. */
    @Override
    public boolean isAvailable() {
        return false;
    }

    /** Rejects all signing requests because this profile intentionally has no platform co-signer. */
    /** @param user account associated with the requested signature */
    /** @throws IllegalStateException because platform signing is not configured */
    @Override
    public String sign(UserDataBase user) {
        throw new IllegalStateException("Platform transaction co-signing is not configured.");
    }
}
