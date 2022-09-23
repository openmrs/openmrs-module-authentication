package org.openmrs.module.authentication.web.scheme;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;
import org.openmrs.module.authentication.web.BaseWebAuthenticationTest;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
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
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.credential.admin", "adminPassword");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		authenticationSession = new MockAuthenticationSession(request);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockBasicWebAuthenticationScheme.class));
		authenticationScheme = (MockBasicWebAuthenticationScheme) scheme;
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("basic"));
	}

	@Test
	public void shouldGetCompleteCredentialsOrReturnNull() {
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.setParameter("uname", "admin");
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.removeParameter("uname");
		request.setParameter("pw", "test");
		assertThat(authenticationScheme.getCredentials(authenticationSession), nullValue());
		request.setParameter("uname", "admin");
		request.setParameter("pw", "adminPassword");
		AuthenticationCredentials credentials = authenticationScheme.getCredentials(authenticationSession);
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("admin"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("basic"));
	}

	@Test
	public void shouldGetChallengeUrlIfNoCredentialsInSession() {
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/login"));
		BasicAuthenticationCredentials credentials = new BasicAuthenticationCredentials(
				"basic", "admin", "adminPassword"
		);
		authenticationSession.getAuthenticationContext().addCredentials(credentials);
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		BasicAuthenticationCredentials credentials = new BasicAuthenticationCredentials(
				"basic", "admin", "adminPassword"
		);
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("basic"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateWithInValidCredentials() {
		BasicAuthenticationCredentials credentials = new BasicAuthenticationCredentials(
				"basic", "admin", "test"
		);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}
}
