package org.openmrs.module.authentication.web.scheme;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.PrimaryAuthenticationCredentials;
import org.openmrs.module.authentication.credentials.TwoFactorAuthenticationCredentials;
import org.openmrs.module.authentication.web.BaseWebAuthenticationTest;
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

public class TwoFactorAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	TwoFactorAuthenticationScheme authenticationScheme;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "2fa");
		AuthenticationConfig.setProperty("authentication.scheme.2fa.type", TwoFactorAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.primaryOptions", "primary");
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.secondaryOptions", "secondary");
		AuthenticationConfig.setProperty("authentication.scheme.primary.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.loginPage", "/primaryLogin");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.usernameParam", "uname");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.passwordParam", "pw");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users", "admin,tester");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.admin.password", "adminPassword");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.tester.password", "primaryPw");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.tester.secondaryType", "secondary");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.loginPage", "/secondaryLogin");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.usernameParam", "uname2");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.passwordParam", "pw2");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.users", "tester");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.users.tester.password", "secondaryPw");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(TwoFactorAuthenticationScheme.class));
		authenticationScheme = (TwoFactorAuthenticationScheme) scheme;
	}

	protected TwoFactorAuthenticationCredentials primaryAuth(String username, String password) {
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
		return (TwoFactorAuthenticationCredentials) authenticationScheme.getCredentials(authenticationSession);
	}

	protected TwoFactorAuthenticationCredentials secondaryAuth(String username, String password) {
		request = newPostRequest("192.168.1.1", "/login");
		if (username != null) {
			request.setParameter("uname2", username);
		}
		if (password != null) {
			request.setParameter("pw2", password);
		}
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		return (TwoFactorAuthenticationCredentials) authenticationScheme.getCredentials(authenticationSession);
	}

	protected AuthenticationCredentials getCredentialsFromContext(String schemeId) {
		return authenticationSession.getAuthenticationContext().getCredentials(schemeId);
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("2fa"));
		assertThat(authenticationScheme.getPrimaryOptions().size(), equalTo(1));
		assertThat(authenticationScheme.getPrimaryOptions().get(0), equalTo("primary"));
		assertThat(authenticationScheme.getSecondaryOptions().size(), equalTo(1));
		assertThat(authenticationScheme.getSecondaryOptions().get(0), equalTo("secondary"));
	}

	@Test
	public void getCredentialsShouldReturnNullIfNoPrimaryAuthentication() {
		TwoFactorAuthenticationCredentials credentials = primaryAuth(null, null);
		assertThat(credentials, nullValue());
	}

	@Test
	public void getCredentialsShouldReturnValidCredentialsIfNoSecondaryAuthenticationRequired() {
		TwoFactorAuthenticationCredentials credentials = primaryAuth("admin", "adminPassword");
		assertThat(credentials, notNullValue());
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), nullValue());
	}

	@Test
	public void getCredentialsShouldNullifyPrimaryCredentialsIfInvalid() {
		AuthenticationCredentials credentials = primaryAuth("admin", "test");
		assertThat(credentials, nullValue());
		assertThat(getCredentialsFromContext("primary"), nullValue());
		assertThat(getCredentialsFromContext("secondary"), nullValue());
	}

	@Test
	public void getCredentialsShouldLogEventIfPrimaryAuthenticationFails() {
		primaryAuth("admin", "test");
		assertLastLogContains("marker=PRIMARY_AUTHENTICATION_FAILED");
	}

	@Test
	public void getCredentialsShouldGetSecondaryCredentialsIfPrimaryCredentialsAreValid() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThat(credentials, nullValue());
		assertThat(getCredentialsFromContext("primary"), notNullValue());
		assertThat(getCredentialsFromContext("secondary"), nullValue());
		credentials = secondaryAuth("tester", "secondaryPw");
		assertThat(credentials, notNullValue());
		assertThat(getCredentialsFromContext("primary"), notNullValue());
		assertThat(getCredentialsFromContext("secondary"), notNullValue());
	}

	@Test
	public void getCredentialsShouldReturnNullIfSecondaryCredentialsMissing() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThat(credentials, nullValue());
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryCredentialsAreMissing() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials(authenticationScheme.schemeId);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryAuthenticationFails() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "test"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetPrimaryCredentialsIfAuthenticationFails() {
		primaryAuth("tester", "test");
		AuthenticationCredentials credentials = secondaryAuth("tester", "secondaryPw");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		assertThat(context.getCredentials("primary"), nullValue());
		assertThat(context.getCredentials("secondary"), nullValue());
	}

	@Test
	public void shouldAuthenticateIfPrimarySucceedsAndSecondaryNotConfigured() {
		AuthenticationCredentials credentials = primaryAuth("admin", "adminPassword");
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryMissing() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryFails() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetSecondaryCredentialsIfSecondaryAuthenticationFails() {
		primaryAuth("tester", "primaryPw");
		AuthenticationCredentials credentials = secondaryAuth("tester", "test");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		assertThat(context.getCredentials("primary"), notNullValue());
		assertThat(context.getCredentials("secondary"), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		AuthenticationCredentials credentials = primaryAuth("admin", "adminPassword");
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}

	@Test
	public void shouldGetPrimaryAuthenticationSchemeFromDefault() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme().getSchemeId(), equalTo("primary"));
	}

	@Test
	public void shouldThrowExceptionIfNoDefaultPrimaryAuthenticationSchemeConfigured() {
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.primaryOptions", "");
		authenticationScheme = (TwoFactorAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.getPrimaryAuthenticationScheme());
	}

	@Test
	public void shouldGetSecondaryAuthenticationScheme() {
		primaryAuth("tester", "primaryPw");
		secondaryAuth("tester", "secondaryPw");
		assertThat(authenticationScheme.getSecondaryAuthenticationScheme(
				authenticationSession.getAuthenticatedUser()
		).getSchemeId(), equalTo("secondary"));
	}
}
