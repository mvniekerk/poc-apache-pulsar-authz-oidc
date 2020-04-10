package za.co.koperfontein.poc.pulsar.oidc;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.authorization.PulsarAuthorizationProvider;
import org.apache.pulsar.broker.cache.ConfigurationCacheService;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class AuthorizationProviderOidc implements AuthorizationProvider {
    public ServiceConfiguration conf;
    public ConfigurationCacheService configCache;
    private PulsarAuthorizationProvider defaultProvider;

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
}
