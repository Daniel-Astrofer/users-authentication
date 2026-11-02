package com.kerosene.sovereign.quorum;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.kerosene.security.infra.SuicideService;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/** In-memory quorum failure tracker that suspends writes after the configured outage window. */
@Service
public class DefaultFailStopPolicy implements FailStopPolicy {

    /** Logger for quorum state transitions and write rejection. */
    private static final Logger logger = LoggerFactory.getLogger(DefaultFailStopPolicy.class);

    private final SuicideService suicideService;
    private final Duration failStopWindow;
    private final boolean hardHaltEnabled;
    private final AtomicInteger consecutiveQuorumFailures = new AtomicInteger(0);
    private volatile boolean failStopMode = false;
    private volatile Instant lastQuorumSuccess = Instant.now();

    /** Creates the policy with hard JVM halt disabled.
     * @param suicideService process halt integration used when explicitly enabled
     * @param failStopWindowMs outage duration before automatic fail-stop
     */
    public DefaultFailStopPolicy(SuicideService suicideService, long failStopWindowMs) {
        this(suicideService, failStopWindowMs, false);
    }

    /** Creates the policy with configured outage window and optional hard halt.
     * @param suicideService process halt integration used when enabled
     * @param failStopWindowMs outage duration before automatic fail-stop
     * @param hardHaltEnabled whether fail-stop invokes immediate process termination
     */
    @org.springframework.beans.factory.annotation.Autowired
    public DefaultFailStopPolicy(
            SuicideService suicideService,
            @Value("${quorum.fail-stop-window-ms:30000}") long failStopWindowMs,
            @Value("${quorum.fail-stop-hard-halt:false}") boolean hardHaltEnabled) {
        this.suicideService = suicideService;
        this.failStopWindow = Duration.ofMillis(failStopWindowMs);
        this.hardHaltEnabled = hardHaltEnabled;
    }

    @Override
    /** @return current fail-stop flag */
    public boolean isFailStopMode() {
        return failStopMode;
    }

    @Override
    /** @return timestamp of the last successful quorum check */
    public Instant lastQuorumSuccess() {
        return lastQuorumSuccess;
    }

    @Override
    /** @return consecutive failure count */
    public int consecutiveQuorumFailures() {
        return consecutiveQuorumFailures.get();
    }

    @Override
    /** Throws {@link SplitBrainException} when writes are suspended.
     * @param transactionHash transaction identifier for the diagnostic log
     */
    public void assertWritesAllowed(String transactionHash) {
        if (!failStopMode) {
            return;
        }

        logger.error("[SPLIT-BRAIN FAIL-STOP] Transaction {} rejected. Writes are suspended.",
                transactionHash);
        throw new SplitBrainException(
                "Kerosene is in Fail-Stop mode due to network partition. "
                        + "Transaction rejected to preserve ledger consistency.");
    }

    @Override
    /** Records quorum recovery and resets the failure counter. */
    public void recordQuorumSuccess() {
        consecutiveQuorumFailures.set(0);
        lastQuorumSuccess = Instant.now();
    }

    @Override
    /** Records an outage and enters fail-stop once it exceeds the configured window.
     * @param reason description of the quorum failure
     */
    public void recordQuorumFailure(String reason) {
        int failures = consecutiveQuorumFailures.incrementAndGet();
        long msSinceLastSuccess = Duration.between(lastQuorumSuccess, Instant.now()).toMillis();
        logger.warn("[Quorum Fail-Stop] Quorum failure {}. No successful quorum for {} ms. Reason: {}",
                failures, msSinceLastSuccess, reason);

        if (msSinceLastSuccess > failStopWindow.toMillis()) {
            enterFailStop(reason + ". No quorum for " + msSinceLastSuccess + " ms.");
        }
    }

    @Override
    /** Suspends writes; invokes the hard halt integration only when configured.
     * @param reason explanation for the state transition
     */
    public void enterFailStop(String reason) {
        if (failStopMode) {
            logger.error("[Quorum Fail-Stop] Fail-stop already active. Reason: {}", reason);
            return;
        }

        failStopMode = true;
        logger.error("[CRITICAL] Split-brain risk detected. Entering fail-stop mode. Reason: {}", reason);
        if (!hardHaltEnabled) {
            logger.error("[Quorum Fail-Stop] Hard JVM halt is disabled. Writes remain suspended until quorum is restored.");
            return;
        }

        suicideService.triggerInstantSuicide(reason);
    }

    @Override
    /** Clears fail-stop and resets the quorum health timestamps and counter. */
    public void clearFailStop() {
        failStopMode = false;
        consecutiveQuorumFailures.set(0);
        lastQuorumSuccess = Instant.now();
    }
}
