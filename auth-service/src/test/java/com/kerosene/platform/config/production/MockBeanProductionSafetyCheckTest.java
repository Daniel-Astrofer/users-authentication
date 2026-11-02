package com.kerosene.platform.config.production;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.mock.env.MockEnvironment;
import com.kerosene.platform.config.ProductionProfileSafetyGate;
import static org.assertj.core.api.Assertions.assertThat;

class MockBeanProductionSafetyCheckTest {
    @Test void acceptsProductionGateAndStillRejectsMockBeans() {
        var beans = new DefaultListableBeanFactory();
        beans.registerBeanDefinition("gate", new RootBeanDefinition(ProductionProfileSafetyGate.class));
        var context = new ProductionSafetyContext(new MockEnvironment(), beans);
        new MockBeanProductionSafetyCheck(null).handle(context);
        assertThat(context.violations()).isEmpty();
        beans.registerBeanDefinition("fake", new RootBeanDefinition(FakeMockSigner.class));
        var unsafe = new ProductionSafetyContext(new MockEnvironment(), beans);
        new MockBeanProductionSafetyCheck(null).handle(unsafe);
        assertThat(unsafe.violations()).anyMatch(v -> v.contains("FakeMockSigner"));
    }
    static class FakeMockSigner {}
}
