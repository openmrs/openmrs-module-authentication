package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class BasicWebAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockBasicWebAuthenticationScheme authenticationScheme;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "basic");
		AuthenticationConfig.setProperty("authentication.scheme.basic.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.loginPage", "/login");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.usernameParam", "uname");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.passwordParam", "pw");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.users", "admin");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.users.admin.password", "adminPassword");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockBasicWebAuthenticationScheme.class));
		authenticationScheme = (MockBasicWebAuthenticationScheme) scheme;
		authenticationSession = new MockAuthenticationSession(session);
		UserLoginTracker.setLoginOnThread(authenticationSession.getUserLogin());
	}

	@AfterEach
	@Override
	public void teardown() {
		UserLoginTracker.removeLoginFromThread();
		super.teardown();
	}

	protected AuthenticationCredentials getCredentials(String username, String password) {
		request = newPostRequest("192.168.1.1", "/login");
		if (username != null) {
			request.setParameter("uname", username);
		}
		if (password != null) {
			request.setParameter("pw", password);
		}
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		return authenticationScheme.getCredentials(authenticationSession);
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("basic"));
	}

	@Test
	public void shouldGetCompleteCredentialsOrReturnNull() {
		assertThat(getCredentials(null, null), nullValue());
		assertThat(getCredentials("admin", null), nullValue());
		assertThat(getCredentials(null, "test"), nullValue());
		AuthenticationCredentials credentials = getCredentials("admin", "adminPassword");
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("admin"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("basic"));
	}

	@Test
	public void shouldReturnNullIfNoCredentialsInSession() {
		assertThat(getCredentials(null, null), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		AuthenticationCredentials credentials = getCredentials("admin", "adminPassword");
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("basic"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		AuthenticationCredentials credentials = getCredentials("admin", "test");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}
}
