package za.co.koperfontein.poc.pulsar.oidc;

import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;

public class AuthenticationProviderOidc implements AuthenticationProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationProviderOidc.class.getName());

    final static String HTTP_HEADER_NAME = "Authorization";
    final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

    final static String OIDC = "oidc";

    @Override
    public void initialize(ServiceConfiguration config) throws IOException {

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

    @Override
    public void close() throws IOException {
        // noop
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

    private String parseBiscuit(final String biscuit) throws AuthenticationException {
        LOGGER.info("Biscuit to parse: {}", biscuit);

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
