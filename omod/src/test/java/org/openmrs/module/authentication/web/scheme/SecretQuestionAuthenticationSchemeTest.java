package org.openmrs.module.authentication.web.scheme;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.SecretQuestionAuthenticationCredentials;
import org.openmrs.module.authentication.web.BaseWebAuthenticationTest;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockSecretQuestionAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
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
	MockSecretQuestionAuthenticationScheme authenticationScheme;
	User candidateUser;

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
		candidateUser = new User();
		candidateUser.setUsername("testing");
		authenticationSession = new MockAuthenticationSession(request, newResponse());
		authenticationSession.getAuthenticationContext().setCandidateUser(candidateUser);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockSecretQuestionAuthenticationScheme.class));
		authenticationScheme = (MockSecretQuestionAuthenticationScheme) scheme;
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("secret"));
	}

	@Test
	public void shouldGetCompleteCredentialsOrReturnNull() {
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.setParameter("secretQ", "Favorite color?");
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.removeParameter("secretQ");
		request.setParameter("secretA", "Red");
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.setParameter("secretQ", "Favorite color?");
		request.setParameter("secretA", "Red");
		AuthenticationCredentials credentials = authenticationScheme.getCredentials(authenticationSession);
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("secret"));
	}

	@Test
	public void shouldGetChallengeUrlIfNoCredentialsInSession() {
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/secretQuestion"));
		SecretQuestionAuthenticationCredentials credentials = new SecretQuestionAuthenticationCredentials(
				"secret", candidateUser, "testing question", "testing answer"
		);
		authenticationSession.getAuthenticationContext().addCredentials(credentials);
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		SecretQuestionAuthenticationCredentials credentials = new SecretQuestionAuthenticationCredentials(
				"secret", candidateUser, "testing question", "testing answer"
		);
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("secret"));
		assertThat(authenticated.getUser().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		SecretQuestionAuthenticationCredentials credentials = new SecretQuestionAuthenticationCredentials(
				"secret", candidateUser, "testing question", "incorrect answer"
		);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}
}
