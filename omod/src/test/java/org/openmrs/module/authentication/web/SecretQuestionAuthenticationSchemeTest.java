package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.TestAuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockSecretQuestionAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecretQuestionAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockSecretQuestionAuthenticationScheme authenticationScheme;
	User candidateUser;
	UserLogin userLogin;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "secret");
		AuthenticationConfig.setProperty("authentication.scheme.secret.type", MockSecretQuestionAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.secret.config.loginPage", "/secretQuestion");
		AuthenticationConfig.setProperty("authentication.scheme.secret.config.questionParam", "secretQ");
		AuthenticationConfig.setProperty("authentication.scheme.secret.config.answerParam", "secretA");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		response = newResponse();
		candidateUser = new User();
		candidateUser.setUsername("testing");
		authenticationSession = new MockAuthenticationSession(request, newResponse());
		userLogin = authenticationSession.getUserLogin();
		userLogin.addUnvalidatedCredentials(new TestAuthenticationCredentials("test", candidateUser));
		userLogin.authenticationSuccessful("test", new BasicAuthenticated(candidateUser, "test"));
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockSecretQuestionAuthenticationScheme.class));
		authenticationScheme = (MockSecretQuestionAuthenticationScheme) scheme;
	}

	protected AuthenticationCredentials getCredentials(String question, String answer) {
		request = newPostRequest("192.168.1.1", "/login");
		if (question != null) {
			request.setParameter("secretQ", question);
		}
		if (answer != null) {
			request.setParameter("secretA", answer);
		}
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		return authenticationScheme.getCredentials(authenticationSession);
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("secret"));
	}

	@Test
	public void shouldGetCompleteCredentialsOrReturnNull() {
		assertThat(getCredentials(null, null), nullValue());
		assertThat(getCredentials("Favorite color?", null), nullValue());
		assertThat(getCredentials(null, "Red"), nullValue());
		AuthenticationCredentials credentials = getCredentials("Favorite color?", "Red");
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("secret"));
	}

	@Test
	public void shouldReturnNullIfNoCredentialsInSession() {
		assertThat(getCredentials(null, null), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		AuthenticationCredentials credentials = getCredentials("testing question", "testing answer");
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("secret"));
		assertThat(authenticated.getUser().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		AuthenticationCredentials credentials = getCredentials("testing question", "incorrect answer");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}
}
