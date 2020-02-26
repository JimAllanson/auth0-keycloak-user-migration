package uk.org.teessidehackspace.keycloak.provider;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.List;

public class Auth0UserStorageProviderFactory implements UserStorageProviderFactory<Auth0UserStorageProvider> {

    @Override
    public Auth0UserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new Auth0UserStorageProvider(session, model);
    }

    @Override
    public String getId() {
        return "auth0-user-provider";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("auth0_domain")
                .label("Auth0 Domain")
                .helpText("Auth0 Domain")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("")
                .add()
                .property()
                .name("auth0_client_id")
                .label("Auth0 Client ID")
                .helpText("Client ID for Keycloak in Auth0")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("")
                .add()
                .property()
                .name("auth0_client_secret")
                .label("Auth0 Client Secret")
                .helpText("Client secret for keycloak in Auth 0")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("")
                .add()
                .build();
    }
}
