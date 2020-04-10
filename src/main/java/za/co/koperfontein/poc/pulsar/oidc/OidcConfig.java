package za.co.koperfontein.poc.pulsar.oidc;

import io.quarkus.oidc.runtime.OidcTenantConfig;
import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pulsar.broker.ServiceConfiguration;

import java.time.Duration;
import java.time.temporal.TemporalUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

public class OidcConfig extends OidcTenantConfig {
    public static final String OIDC_AUTH_SERVER_URL = "oidc-auth-server-url";
    public static final String OIDC_CLIENT_ID = "oidc-client-id";
    public static final String OIDC_CONNECTION_DELAY = "oidc-connection-delay";
    public static final String OIDC_INTROSPECTION_PATH = "oidc-introspection-path";
    public static final String OIDC_JWKS_PATH = "oidc-jwks-path";
    public static final String OIDC_PUBLIC_KEY = "oidc-public-key";
    public static final String OIDC_TENANT_ENABLED = "oidc-tenant-enabled";

    public static final String OIDC_AUTHENTICATION_COOKIE_PATH = "oidc-authentication-cookie-path";
    public static final String OIDC_AUTHENTICATION_EXTRA_PATHS = "oidc-authentication-extra-paths";
    public static final String OIDC_AUTHENTICATION_REDIRECT_PATHS = "oidc-authentication-redirect-paths";
    public static final String OIDC_AUTHENTICATION_RESTORE_PATH_AFTER_REDIRECT = "oidc-authentication-restore-path-after-redirect";
    public static final String OIDC_AUTHENTICATION_SCOPES = "oidc-authentication-scopes";

    public static final String OIDC_SECRET = "oidc-secret";
    public static final String OIDC_CLIENT_SECRET = "oidc-client-secret";
    public static final String OIDC_CLIENT_METHOD = "oidc-client-method";

    public static final String OIDC_ROLE_CLAIM_PATH = "oidc-role-claim-path";
    public static final String OIDC_ROLE_CLAIM_SEPARATOR = "oidc-role-claim-separator";

    public static final String OIDC_TOKEN_AUDIENCE = "oidc-token-audience";
    public static final String OIDC_TOKEN_EXPIRATION_GRACE = "oidc-token-expiration-grace";
    public static final String OIDC_TOKEN_ISSUER = "oidc-token-issuer";
    public static final String OIDC_TOKEN_PRINCIPAL = "oidc-token-principal-claim";

    public OidcConfig(ServiceConfiguration conf) {
        this.applicationType = ApplicationType.SERVICE;
        setIfNotNull(OIDC_AUTH_SERVER_URL, conf, this::setAuthServerUrl);
        setIfNotNull(OIDC_CLIENT_ID, conf, this::setClientId);
        this.connectionDelay = Optional.ofNullable(conf.getProperty(OIDC_CONNECTION_DELAY))
                .map(b -> (long) b).map(Duration::ofMillis);
        setIfNotNull(OIDC_INTROSPECTION_PATH, conf, this::setIntrospectionPath);
        setIfNotNull(OIDC_JWKS_PATH, conf, this::setJwksPath);
        setIfNotNull(OIDC_PUBLIC_KEY, conf, this::setJwksPath);
        this.tenantEnabled = (boolean) conf.getProperty(OIDC_TENANT_ENABLED);

        this.setAuthentication(authentication(conf));
        this.setCredentials(credentials(conf));
        this.setRoles(roles(conf));
        this.setToken(token(conf));
    }

    private static OidcTenantConfig.Authentication authentication(ServiceConfiguration conf) {
        OidcTenantConfig.Authentication ret = new Authentication();
        ret.setCookiePath(
                Optional.ofNullable(conf.getProperty(OIDC_AUTHENTICATION_COOKIE_PATH))
                .map(b -> (String) b)
        );
        ret.setExtraParams(
                Optional.ofNullable(conf.getProperty(OIDC_AUTHENTICATION_EXTRA_PATHS))
                .map(b -> (Map<String, String>) b ).orElse(new HashedMap<>())
        );
        if (conf.getProperties().containsKey(OIDC_AUTHENTICATION_REDIRECT_PATHS)) {
            ret.setRedirectPath((String) conf.getProperty(OIDC_AUTHENTICATION_REDIRECT_PATHS));
        }
        ret.setRestorePathAfterRedirect((boolean) conf.getProperty(OIDC_AUTHENTICATION_RESTORE_PATH_AFTER_REDIRECT));
        ret.setScopes(
                Optional.ofNullable(conf.getProperty(OIDC_AUTHENTICATION_SCOPES))
                .map(b -> (String) b).map(b -> Arrays.asList(b.split(",")))
        );
        return ret;
    }

    private static OidcTenantConfig.Credentials credentials(ServiceConfiguration conf) {
        OidcTenantConfig.Credentials ret = new OidcTenantConfig.Credentials();
        ret.setSecret((String) conf.getProperty(OIDC_SECRET));
        Optional<OidcTenantConfig.Credentials.Secret> secret =
                conf.getProperties().containsKey(OIDC_CLIENT_SECRET) && conf.getProperties().containsKey(OIDC_CLIENT_METHOD)
                ? Optional.of(
                        Pair.of(
                            (String) conf.getProperty(OIDC_CLIENT_SECRET),
                            (String) conf.getProperty(OIDC_CLIENT_METHOD)
                        )
                ).map(b -> {
                    OidcTenantConfig.Credentials.Secret v = new Credentials.Secret();
                    v.setValue(b.getLeft());
                    v.setMethod(Credentials.Secret.Method.valueOf(b.getRight()));
                    return v;
                })
                : Optional.empty();
        ret.setClientSecret(secret.orElse(null));
        return ret;
    }

    private static OidcTenantConfig.Token token(ServiceConfiguration conf) {
        OidcTenantConfig.Token ret = new OidcTenantConfig.Token();
        ret.audience = Optional.ofNullable(conf.getProperty(OIDC_TOKEN_AUDIENCE))
                .map(b -> (String) b).map(b -> Arrays.asList(b.split(",")));
        ret.expirationGrace = Optional.ofNullable(conf.getProperty(OIDC_TOKEN_EXPIRATION_GRACE))
                .map(b -> (Integer) b);
        ret.issuer = Optional.ofNullable(conf.getProperty(OIDC_TOKEN_ISSUER))
                .map(b -> (String) b);
        ret.principalClaim = Optional.ofNullable(conf.getProperty(OIDC_TOKEN_PRINCIPAL))
                .map(b -> (String) b);
        return ret;
    }

    private static OidcTenantConfig.Roles roles(ServiceConfiguration conf) {
        OidcTenantConfig.Roles ret = new OidcTenantConfig.Roles();
        setIfNotNull(OIDC_ROLE_CLAIM_PATH, conf, ret::setRoleClaimPath);
        setIfNotNull(OIDC_ROLE_CLAIM_SEPARATOR, conf, ret::setRoleClaimSeparator);
        return ret;
    }

    private static void setIfNotNull(String key, ServiceConfiguration conf, Consumer<String> setter) {
        if (conf.getProperties().containsKey(key)) {
            setter.accept((String) conf.getProperty(key));
        }
    }
}
