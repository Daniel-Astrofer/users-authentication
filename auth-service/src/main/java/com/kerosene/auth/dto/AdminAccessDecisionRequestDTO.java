package com.kerosene.auth.dto;

/** Request carrying the trusted administrator's decision for a pending access attempt. */
public class AdminAccessDecisionRequestDTO {

    /** Creates an empty request bean for JSON deserialization. */
    public AdminAccessDecisionRequestDTO() {
    }

    /** Decision value interpreted by the approval endpoint, typically approve or deny. */
    private String decision;

    /**
     * Returns the requested decision.
     *
     * @return decision code consumed by the admin access service
     */
    public String getDecision() {
        return decision;
    }

    /**
     * Sets the requested access decision.
     *
     * @param decision approval or denial code validated by the service
     */
    public void setDecision(String decision) {
        this.decision = decision;
    }
}
