package com.kerosene.integration.financial;

import com.kerosene.common.financial.notification.FinancialNotificationAuditPort;
import com.kerosene.common.financial.notification.FinancialNotificationPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Supplies no-op notification boundaries only when no concrete financial adapters are configured. */
@Configuration
public class FinancialFallbackConfiguration {

    /** Creates the conditional adapter configuration. */
    public FinancialFallbackConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean(FinancialNotificationAuditPort.class)
    /** Provides a no-op audit adapter when the application has no audit notification integration.
     * @return default audit boundary bean
     */
    public FinancialNotificationAuditPort noopFinancialNotificationAuditPort() {
        return new NoopFinancialNotificationAuditPort();
    }

    @Bean
    @ConditionalOnMissingBean(FinancialNotificationPort.class)
    /** Provides a no-op notification adapter when the application has no financial notifier.
     * @return default notification boundary bean
     */
    public FinancialNotificationPort noopFinancialNotificationPort() {
        return new NoopFinancialNotificationPort();
    }
}
