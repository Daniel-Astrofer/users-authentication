package com.kerosene.sovereign.quorum;

/** Supplies the configured set of peers that form the current quorum topology. */
public interface QuorumMembership {

    /** Resolves the topology from current service configuration.
     * @return peer topology used for quorum operations
     */
    QuorumTopology current();
}
