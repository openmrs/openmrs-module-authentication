package org.openmrs.module.authentication.web.scheme;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.credentials.SecondaryAuthenticationCredentials;
import org.openmrs.module.authentication.web.BaseWebAuthenticationTest;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockSecretQuestionAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.util.HashMap;
import java.util.Map;

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
		authenticationSession.getAuthenticationContext().setCandidateUser(candidateUser);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockSecretQuestionAuthenticationScheme.class));
		authenticationScheme = (MockSecretQuestionAuthenticationScheme) scheme;
	}

	protected SecondaryAuthenticationCredentials getCredentials(String question, String answer) {
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
		return (SecondaryAuthenticationCredentials) authenticationScheme.getCredentials(authenticationSession);
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
		SecondaryAuthenticationCredentials credentials = getCredentials("Favorite color?", "Red");
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("secret"));
	}

	@Test
	public void shouldRedirectToChallengeUrlIfNoCredentialsInSession() {
		getCredentials(null, null);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/secretQuestion"));
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		Map<String, String> data = new HashMap<>();
		data.put("question", "testing question");
		data.put("answer", "testing answer");
		SecondaryAuthenticationCredentials credentials = new SecondaryAuthenticationCredentials(
				"secret", candidateUser, data
		);
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("secret"));
		assertThat(authenticated.getUser().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		Map<String, String> data = new HashMap<>();
		data.put("testing question", "incorrect answer");
		SecondaryAuthenticationCredentials credentials = new SecondaryAuthenticationCredentials(
				"secret", candidateUser, data
		);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}
}
