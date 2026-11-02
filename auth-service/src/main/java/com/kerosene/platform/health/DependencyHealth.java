package com.kerosene.platform.health;

import java.util.Map;

/** Health snapshot for one named dependency, including severity and probe details.
 * @param name dependency identifier used by health reporting
 * @param status probe result such as UP or DOWN
 * @param critical whether dependency failure blocks service readiness
 * @param latencyMs time spent probing the dependency
 * @param message human-readable probe summary
 * @param details structured diagnostics safe for the health response
 */
public record DependencyHealth(
        String name,
        String status,
        boolean critical,
        long latencyMs,
        String message,
        Map<String, Object> details) {

    /** Returns whether the dependency status is exactly {@code UP}.
     * @return true only for an UP status
     */
    public boolean isUp() {
        return "UP".equals(status);
    }

    /** Returns whether the dependency status is exactly {@code DOWN}.
     * @return true only for a DOWN status
     */
    public boolean isDown() {
        return "DOWN".equals(status);
    }
}
