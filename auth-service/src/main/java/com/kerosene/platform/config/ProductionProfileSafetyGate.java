package com.kerosene.platform.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import java.util.List;
import com.kerosene.platform.config.production.ProductionProfileDetector;
import com.kerosene.platform.config.production.ProductionSafetyCheckChain;

/**
 * Fails closed when a production profile is started with simulation beans or
 * financial mock flags enabled.
 *
 * The only explicit exceptions are the temporary flows requested for local
 * balance deposit credit and vouchers.
 */
@Component
public class ProductionProfileSafetyGate implements ApplicationRunner {

    private final ProductionProfileDetector productionProfileDetector;
    private final ProductionSafetyCheckChain productionSafetyCheckChain;

    public ProductionProfileSafetyGate(
            ProductionProfileDetector productionProfileDetector,
            ProductionSafetyCheckChain productionSafetyCheckChain) {
        this.productionProfileDetector = productionProfileDetector;
        this.productionSafetyCheckChain = productionSafetyCheckChain;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!productionProfileDetector.isProductionProfile()) {
            return;
        }

        List<String> violations = productionSafetyCheckChain.collectViolations();

        if (!violations.isEmpty()) {
            throw new IllegalStateException(
                    "Production profile refused to start because unsafe mocks/stubs are active: "
                            + String.join("; ", violations));
        }
    }
}
