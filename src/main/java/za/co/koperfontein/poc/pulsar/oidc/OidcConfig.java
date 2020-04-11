package za.co.koperfontein.poc.pulsar.oidc;

import io.quarkus.oidc.runtime.OidcTenantConfig;
import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

public class OidcConfig extends OidcTenantConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcConfig.class.getName());
    public static final String OIDC_AUTH_SERVER_URL = "oidcAuthServerUrl";
    public static final String OIDC_CLIENT_ID = "oidcClientId";
    public static final String OIDC_CONNECTION_DELAY = "oidcConnectionDelay";
    public static final String OIDC_INTROSPECTION_PATH = "oidcIntrospectionPath";
    public static final String OIDC_JWKS_PATH = "oidcJwksPath";
    public static final String OIDC_PUBLIC_KEY = "oidcPublicKey";
    public static final String OIDC_TENANT_ENABLED = "oidcTenantEnabled";

    public static final String OIDC_AUTHENTICATION_COOKIE_PATH = "oidcAuthenticationCookiePath";
    public static final String OIDC_AUTHENTICATION_EXTRA_PATHS = "oidcAuthenticationExtraPaths";
    public static final String OIDC_AUTHENTICATION_REDIRECT_PATHS = "oidcAuthenticationRedirectPaths";
    public static final String OIDC_AUTHENTICATION_RESTORE_PATH_AFTER_REDIRECT = "oidcAuthenticationRestorePathAfterRedirect";
    public static final String OIDC_AUTHENTICATION_SCOPES = "oidcAuthenticationScopes";

    public static final String OIDC_SECRET = "oidcSecret";
    public static final String OIDC_CLIENT_SECRET = "oidcClientSecret";
    public static final String OIDC_CLIENT_METHOD = "oidcClientMethod";

    public static final String OIDC_ROLE_CLAIM_PATH = "oidcRoleClaimPath";
    public static final String OIDC_ROLE_CLAIM_SEPARATOR = "oidcRoleClaimSeparator";

    public static final String OIDC_TOKEN_AUDIENCE = "oidcTokenAudience";
    public static final String OIDC_TOKEN_EXPIRATION_GRACE = "oidcTokenExpirationGrace";
    public static final String OIDC_TOKEN_ISSUER = "oidcTokenIssuer";
    public static final String OIDC_TOKEN_PRINCIPAL_CLAIM = "oidcTokenPrincipalClaim";

    public OidcConfig(ServiceConfiguration conf) {
        this.applicationType = ApplicationType.SERVICE;
        setIfNotNull(OIDC_AUTH_SERVER_URL, conf, this::setAuthServerUrl);
        setIfNotNull(OIDC_CLIENT_ID, conf, this::setClientId);
        this.connectionDelay = Optional.ofNullable(conf.getProperty(OIDC_CONNECTION_DELAY))
                .map(b -> (long) b).map(Duration::ofMillis);
        setIfNotNull(OIDC_INTROSPECTION_PATH, conf, this::setIntrospectionPath);
        setIfNotNull(OIDC_JWKS_PATH, conf, this::setJwksPath);
        setIfNotNull(OIDC_PUBLIC_KEY, conf, this::setJwksPath);
        this.tenantEnabled = true;

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
        ret.principalClaim = Optional.ofNullable(conf.getProperty(OIDC_TOKEN_PRINCIPAL_CLAIM))
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
