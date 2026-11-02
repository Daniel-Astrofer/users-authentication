package com.kerosene.sovereign.quorum;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/** Builds quorum membership from the comma-separated {@code quorum.shard.urls} setting. */
@Service
public class ConfiguredQuorumMembership implements QuorumMembership {

    private final String shardUrlsConfig;

    /** Creates the membership source with the configured peer URL list.
     * @param shardUrlsConfig comma-separated peer URLs, possibly empty
     */
    public ConfiguredQuorumMembership(@Value("${quorum.shard.urls:}") String shardUrlsConfig) {
        this.shardUrlsConfig = shardUrlsConfig;
    }

    @Override
    /** Returns a snapshot of peers parsed from the configured URL list. */
    public QuorumTopology current() {
        List<QuorumPeer> peers = parsePeers();
        return new QuorumTopology(peers);
    }

    /** Trims the configured comma-separated list and discards empty entries.
     * @return immutable list of configured peers
     */
    private List<QuorumPeer> parsePeers() {
        if (shardUrlsConfig == null || shardUrlsConfig.isBlank()) {
            return List.of();
        }

        return Arrays.stream(shardUrlsConfig.split(","))
                .map(String::trim)
                .filter(peer -> !peer.isEmpty())
                .map(QuorumPeer::new)
                .toList();
    }
}
