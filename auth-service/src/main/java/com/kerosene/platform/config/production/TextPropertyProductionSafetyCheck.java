package com.kerosene.platform.config.production;

public class TextPropertyProductionSafetyCheck extends AbstractProductionSafetyCheck {

    public TextPropertyProductionSafetyCheck(ProductionSafetyCheck next) {
        super(next);
    }

    @Override
    protected void inspect(ProductionSafetyContext context) {
        String bitcoinNetwork = context.environment().getProperty("bitcoin.network", "");
        if (!"testnet3".equalsIgnoreCase(bitcoinNetwork) && !"testnet".equalsIgnoreCase(bitcoinNetwork)) {
            context.addViolation("bitcoin.network must be testnet3");
        }
        String corsOrigins = context.environment().getProperty("app.cors.allowed-origins", "");
        if (corsOrigins.isBlank()) {
            context.addViolation("app.cors.allowed-origins must be configured");
        }
        if (corsOrigins.contains("*")) {
            context.addViolation("wildcard CORS is not allowed");
        }
        if (corsOrigins.contains("localhost") || corsOrigins.contains("127.0.0.1")) {
            context.addViolation("localhost CORS origins are not allowed in prod");
        }

        requireSpiffeId(context, "kerosene.workload-identity.own-spiffe-id");
        requireSpiffeId(context, "kerosene.workload-identity.peer-spiffe-id");
        requireSpiffeRole(context, "kerosene.workload-identity.own-spiffe-id", "/service/auth");
        requireSpiffeRole(context, "kerosene.workload-identity.peer-spiffe-id", "/service/kfe");
        String workloadSocket = context.environment().getProperty("kerosene.workload-identity.socket", "");
        if (!workloadSocket.startsWith("unix://")) {
            context.addViolation("kerosene.workload-identity.socket must use a unix:// Workload API endpoint");
        }
        requireHttps(context, "kfe.internal.base-url");
        requireHttps(context, "kfe.remote.base-url");
        if (!context.environment().getProperty("kfe.internal.shared-secret", "").isBlank()) {
            context.addViolation("kfe.internal.shared-secret must be empty when SPIFFE workload identity is enabled");
        }
        int publicPort = context.environment().getProperty("server.port", Integer.class, 8080);
        int internalPort = context.environment().getProperty(
                "kerosene.workload-identity.internal-port", Integer.class, 8443);
        if (publicPort == internalPort) {
            context.addViolation("internal mTLS port must differ from the public server.port");
        }

        String relyingPartyId = context.environment().getProperty("webauthn.relying-party-id", "");
        if (relyingPartyId.isBlank() || "localhost".equalsIgnoreCase(relyingPartyId)) {
            context.addViolation("webauthn.relying-party-id must be a production host");
        }

        // Custody keys, signer rosters and rail configuration belong to KFE.
        // ExternalRailProviderProductionSafetyCheck obtains its authenticated result.
        if (context.environment().getProperty("shard.attestation.secret", "").isBlank()) {
            context.addViolation("shard.attestation.secret must be configured");
        }

    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static void requireSpiffeId(ProductionSafetyContext context, String property) {
        String value = context.environment().getProperty(property, "");
        if (!value.startsWith("spiffe://") || value.indexOf('/', "spiffe://".length()) < 0) {
            context.addViolation(property + " must be an explicit non-root SPIFFE ID");
        }
    }

    private static void requireHttps(ProductionSafetyContext context, String property) {
        if (!context.environment().getProperty(property, "").startsWith("https://")) {
            context.addViolation(property + " must use https:// in prod");
        }
    }

    private static void requireSpiffeRole(
            ProductionSafetyContext context, String property, String requiredSuffix) {
        if (!context.environment().getProperty(property, "").endsWith(requiredSuffix)) {
            context.addViolation(property + " must end with " + requiredSuffix);
        }
    }
}
