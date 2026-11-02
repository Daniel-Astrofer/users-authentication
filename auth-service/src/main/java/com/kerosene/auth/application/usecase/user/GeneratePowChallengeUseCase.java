package com.kerosene.auth.application.usecase.user;

import org.springframework.stereotype.Component;
import com.kerosene.auth.application.service.pow.PowService;

import java.util.Map;

/** Exposes a fresh proof-of-work challenge through the application use-case boundary. */
@Component
public class GeneratePowChallengeUseCase {

    /** Generator that creates the challenge material consumed by the client-side PoW flow. */
    private final PowService powService;

    /**
     * Creates the challenge use case.
     * @param powService proof-of-work challenge generator
     */
    public GeneratePowChallengeUseCase(PowService powService) {
        this.powService = powService;
    }

    /**
     * Generates one challenge and returns it under the public {@code challenge} response key.
     *
     * @return immutable response map containing the generated challenge
     */
    public Map<String, String> execute() {
        return Map.of("challenge", powService.generateChallenge());
    }
}
