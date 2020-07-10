package uk.org.teessidehackspace.keycloak.provider;

import org.jboss.logging.Logger;
import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.FieldsFilter;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.mgmt.users.User;
import com.auth0.net.AuthRequest;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Auth0UserStorageProvider implements UserStorageProvider, CredentialInputValidator, UserLookupProvider {

    private static final Logger logger = Logger.getLogger(Auth0UserStorageProvider.class);

    protected Map<String, UserModel> loadedUsers = new HashMap<>();

    private final KeycloakSession session;
    private final ComponentModel model;

    public Auth0UserStorageProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) return false;
        if (input.getType().equals(PasswordCredentialModel.TYPE)) {
            return validPassword(realm, user, input.getChallengeResponse());
        } else {
            return false;
        }
    }

    public boolean validPassword(RealmModel realm, UserModel user, String password) {
        AuthAPI api = new AuthAPI(model.get("auth0_domain"), model.get("auth0_client_id"), model.get("auth0_client_secret"));
        AuthRequest request = api.login(user.getUsername(), password)
                .setAudience("https://"+model.get("auth0_domain")+"/api/v2/")
                .setScope("openid");
        try {
            TokenHolder holder = request.execute();
            session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(password));
            user.addRequiredAction(UpdateProfileWithUsernameValidation.PROVIDER_ID);
            user.setFederationLink(null);
            return true;
        } catch (APIException exception) {
            logger.error(exception);
        } catch (Auth0Exception exception) {
            logger.error(exception);
        }
        return false;
    }

    public void close() {
    }

    public UserModel getUserById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(username, realm);
    }

    public UserModel getUserByUsername(String username, RealmModel realm) {
        UserModel adapter = loadedUsers.get(username);
        if (adapter == null) {
            AuthAPI api = new AuthAPI(model.get("auth0_domain"), model.get("auth0_client_id"), model.get("auth0_client_secret"));
            AuthRequest request = api.requestToken("https://"+model.get("auth0_domain")+"/api/v2/");

            List<User> listRequest = null;
            try {
                TokenHolder holder = request.execute();

                ManagementAPI mgmt = new ManagementAPI(model.get("auth0_domain"), holder.getAccessToken());
                listRequest = mgmt.users().listByEmail(username, new FieldsFilter()).execute();

                if (listRequest.size() > 0) {
                    User user = listRequest.get(0);
                    adapter = createAdapter(realm, username);
                    loadedUsers.put(username, adapter);
                }
            } catch (Auth0Exception e) {
                logger.error(e);
            }
        }
        return adapter;
    }


    protected UserModel createAdapter(RealmModel realm, String username) {
        UserModel local = session.userLocalStorage().getUserByUsername(username, realm);
        if (local == null) {
            local = session.userLocalStorage().addUser(realm, username);
            local.setEmail(username);
            local.setEnabled(true);
            local.setEmailVerified(true);
            local.setFederationLink(model.getId());
        }
        return local;
    }

    public UserModel getUserByEmail(String email, RealmModel realm) {
        return getUserByUsername(email, realm);
    }
}
