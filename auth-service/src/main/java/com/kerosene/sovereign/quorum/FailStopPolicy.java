package com.kerosene.sovereign.quorum;

import java.time.Instant;

/** Tracks quorum health and gates writes when split-brain risk requires fail-stop behavior. */
public interface FailStopPolicy {

    /** Reports whether fail-stop mode currently suspends writes.
     * @return true when writes are suspended
     */
    boolean isFailStopMode();

    /** Returns the time of the most recent successful quorum check.
     * @return last-success timestamp
     */
    Instant lastQuorumSuccess();

    /** Reports the number of consecutive quorum failures since the last success.
     * @return consecutive failure count
     */
    int consecutiveQuorumFailures();

    /** Rejects a write while fail-stop is active.
     * @param transactionHash transaction identifier to include in diagnostics
     */
    void assertWritesAllowed(String transactionHash);

    /** Clears the failure count and advances the last-success timestamp. */
    void recordQuorumSuccess();

    /** Increments the failure count and may enter fail-stop after the configured window.
     * @param reason reason supplied by the failed quorum operation
     */
    void recordQuorumFailure(String reason);

    /** Suspends writes explicitly, optionally triggering the configured hard halt.
     * @param reason operational explanation for fail-stop activation
     */
    void enterFailStop(String reason);

    /** Resumes writes and resets failure tracking after quorum recovery. */
    void clearFailStop();
}
