package com.kerosene.auth.application.service.identityaccess;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UnavailablePlatformTransactionSignerTest {
    @Test
    void productionBindsRetiredSignerAndStillRejectsSigning() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().setActiveProfiles("prod");
            context.register(UnavailablePlatformTransactionSigner.class);
            context.refresh();
            var signer = context.getBean(PlatformTransactionSignerPort.class);
            assertThat(signer.isAvailable()).isFalse();
            assertThatThrownBy(() -> signer.sign(null)).isInstanceOf(IllegalStateException.class);
        }
    }
}
