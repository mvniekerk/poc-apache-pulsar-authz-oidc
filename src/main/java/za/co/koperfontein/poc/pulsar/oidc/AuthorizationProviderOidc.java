package za.co.koperfontein.poc.pulsar.oidc;

import io.quarkus.oidc.runtime.OidcTenantConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.authorization.PulsarAuthorizationProvider;
import org.apache.pulsar.broker.cache.ConfigurationCacheService;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class AuthorizationProviderOidc implements AuthorizationProvider, AuthenticationProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationProviderOidc.class.getName());
    final static String HTTP_HEADER_NAME = "Authorization";
    final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

    final static String OIDC = "oidc";
    public ServiceConfiguration conf;
    public ConfigurationCacheService configCache;
    private PulsarAuthorizationProvider defaultProvider;
    private OidcTenantConfig oidcConfig;

    public AuthorizationProviderOidc() { }

    public AuthorizationProviderOidc(ServiceConfiguration conf, ConfigurationCacheService configCache)
            throws IOException {
        initialize(conf, configCache);
    }

    @Override
    public void initialize(ServiceConfiguration conf, ConfigurationCacheService configCache) throws IOException {
        this.conf = conf;
        this.configCache = configCache;
        defaultProvider = new PulsarAuthorizationProvider(conf, configCache);
        this.oidcConfig = new OidcConfig(conf);
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if(!role.startsWith("jwt:")) {
            return defaultProvider.canProduceAsync(topicName, role, authenticationData);
        }
        // TODO
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        permissionFuture.complete(true);
        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        if (!role.startsWith("jwt:")) {
            return defaultProvider.canConsumeAsync(topicName, role, authenticationData, subscription);
        }
        // TODO
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        permissionFuture.complete(true);
        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("jwt:")) {
            return defaultProvider.canLookupAsync(topicName, role, authenticationData);
        }
        // TODO
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        permissionFuture.complete(true);
        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("jwt:")) {
            return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
        }
        // TODO
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        permissionFuture.complete(true);
        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> isSuperUser(String role, ServiceConfiguration serviceConfiguration) {
        if (!role.startsWith("jwt:")) {
            return defaultProvider.isSuperUser(role, serviceConfiguration);
        }

        // TODO
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        permissionFuture.complete(true);
        return permissionFuture;
    }

    // TODO should this not be part of the OIDC client setup?

    @Override
    public CompletableFuture<Void> grantPermissionAsync(NamespaceName namespace, Set<AuthAction> actions, String role, String authDataJson) {
        return defaultProvider.grantPermissionAsync(namespace, actions, role, authDataJson);
    }

    @Override
    public CompletableFuture<Void> grantSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName, Set<String> roles, String authDataJson) {
        return defaultProvider.grantSubscriptionPermissionAsync(namespace, subscriptionName, roles, authDataJson);
    }

    @Override
    public CompletableFuture<Void> revokeSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName, String role, String authDataJson) {
        return defaultProvider.revokeSubscriptionPermissionAsync(namespace, subscriptionName, role, authDataJson);
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(TopicName topicName, Set<AuthAction> actions, String role, String authDataJson) {
        return defaultProvider.grantPermissionAsync(topicName, actions, role, authDataJson);
    }

    @Override
    public void close() throws IOException {
        // NOP
    }


    @Override
    public void initialize(ServiceConfiguration config) throws IOException {
        this.oidcConfig = new OidcConfig(config);
    }

    @Override
    public String getAuthMethodName() {
        return OIDC;
    }

    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String biscuit = getJwt(authData);
        return parseBiscuit(biscuit);
    }

    private static String validateJwt(final String jwt) throws AuthenticationException {
        // Key check
        if (StringUtils.isNotBlank(jwt)) {
            return jwt;
        } else {
            throw new AuthenticationException("Blank biscuit found");
        }
    }

    public static String getJwt(AuthenticationDataSource authData) throws AuthenticationException {
        if (authData.hasDataFromCommand()) {
            // Authenticate Pulsar binary connection
            return authData.getCommandData();
        } else if (authData.hasDataFromHttp()) {
            // Authentication HTTP request. The format here should be compliant to RFC-6750
            // (https://tools.ietf.org/html/rfc6750#section-2.1). Eg: Authorization: Bearer xxxxxxxxxxxxx
            String httpHeaderValue = authData.getHttpHeader(HTTP_HEADER_NAME);
            if (httpHeaderValue == null || !httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
                throw new AuthenticationException("Invalid HTTP Authorization header");
            }

            // Remove prefix
            String jwt = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
            return validateJwt(jwt);
        } else {
            throw new AuthenticationException("No JWT credentials passed");
        }
    }

    private String parseBiscuit(final String jwt) throws AuthenticationException {
        LOGGER.info("Jwt to parse: {}", jwt);

//        Either<Error, Biscuit> deser = Biscuit.from_bytes(Base64.getUrlDecoder().decode(biscuit));
//
//        if (deser.isLeft()) {
//            throw new AuthenticationException("Could not deserialize biscuit");
//        } else {
//            Biscuit realBiscuit = deser.get();
//            LOGGER.info("Deserialized biscuit");
//
//            if (realBiscuit.check_root_key(rootKey).isLeft()) {
//                throw new AuthenticationException("This biscuit was not generated with the expected root key");
//            }
//            LOGGER.info("Root key is valid");
//
//            byte[] sealed = realBiscuit.seal(BISCUIT_SEALING_KEY.getBytes()).get();
//            LOGGER.info("Biscuit deserialized and sealed");
//            return "biscuit:" + Base64.getEncoder().encodeToString(sealed);
//        }
        // TODO
        return "";
    }
}
