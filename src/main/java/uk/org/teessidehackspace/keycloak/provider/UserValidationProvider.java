package uk.org.teessidehackspace.keycloak.provider;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.AttributeFormDataProcessor;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserValidationProvider implements FormAction, FormActionFactory {

    private static final Logger logger = Logger.getLogger(UserValidationProvider.class);

    public static final String PROVIDER_ID = "registration-user-creation-custom";

    @Override
    public String getHelpText() {
        return "This action must always be first! Validates the username of the user in validation phase.  In success phase, this will create the user in the database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        context.getEvent().detail(Details.USERNAME, username);
        context.getEvent().detail(Details.EMAIL, email);

        String usernameField = RegistrationPage.FIELD_USERNAME;
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            context.getEvent().detail(Details.USERNAME, email);

            if (Validation.isBlank(email)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
            } else if (!Validation.isEmailValid(email)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
                formData.remove(Validation.FIELD_EMAIL);
            }
            if (errors.size() > 0) {
                context.error(Errors.INVALID_REGISTRATION);
                context.validationError(formData, errors);
                return;
            }
            if (email != null && !context.getRealm().isDuplicateEmailsAllowed() && context.getSession().users().getUserByEmail(email, context.getRealm()) != null) {
                context.error(Errors.EMAIL_IN_USE);
                formData.remove(Validation.FIELD_EMAIL);
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
                context.validationError(formData, errors);
                return;
            }
        } else {
            if (Validation.isBlank(username)) {
                context.error(Errors.INVALID_REGISTRATION);
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.MISSING_USERNAME));
                context.validationError(formData, errors);
                return;
            }

            if (context.getSession().users().getUserByUsername(username, context.getRealm()) != null) {
                context.error(Errors.USERNAME_IN_USE);
                errors.add(new FormMessage(usernameField, Messages.USERNAME_EXISTS));
                formData.remove(Validation.FIELD_USERNAME);
                context.validationError(formData, errors);
                return;
            }

            logger.info("Checking username is valid");
            if(!username.matches("[A-Za-z0-9_-]+")) {
                context.error(Errors.INVALID_REGISTRATION);
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_USERNAME));
                formData.remove(Validation.FIELD_USERNAME);
                context.validationError(formData, errors);
                logger.info("Username is invalid, fail");
                return;
            }
            logger.info("username is valid");

        }
        context.success();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    @Override
    public void success(FormContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            username = formData.getFirst(RegistrationPage.FIELD_EMAIL);
        }
        context.getEvent().detail(Details.USERNAME, username)
                .detail(Details.REGISTER_METHOD, "form")
                .detail(Details.EMAIL, email)
        ;
        UserModel user = context.getSession().users().addUser(context.getRealm(), username);
        user.setEnabled(true);

        user.setEmail(email);
        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);
        AttributeFormDataProcessor.process(formData, context.getRealm(), user);
        context.setUser(user);
        context.getEvent().user(user);
        context.getEvent().success();
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Registration User Creation Custom";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
