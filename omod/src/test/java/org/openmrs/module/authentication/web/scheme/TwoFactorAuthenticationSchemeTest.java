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

import java.util.List;

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

	protected TwoFactorAuthenticationCredentials get2faCredentials() {
		return (TwoFactorAuthenticationCredentials) authenticationSession.getAuthenticationContext().getCredentials("2fa");
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
	public void getCredentialsShouldReturnNullAndRedirectToPrimaryLoginIfNoPrimaryAuthentication() {
		TwoFactorAuthenticationCredentials credentials = primaryAuth(null, null);
		assertThat(credentials, nullValue());
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/primaryLogin"));
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
		primaryAuth("admin", "test");
		TwoFactorAuthenticationCredentials credentials = get2faCredentials();
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		assertThat(authenticationSession.getAuthenticationContext().getCredentials("primary"), nullValue());
	}

	@Test
	public void getCredentialsShouldLogEventIfPrimaryAuthenticationFails() {
		primaryAuth("admin", "test");
		assertLastLogContains("marker=PRIMARY_AUTHENTICATION_FAILED");
	}

	@Test
	public void getCredentialsShouldNotGetSecondaryCredentialsUnlessPrimaryCredentialsAreValid() {
		primaryAuth(null, null);
		TwoFactorAuthenticationCredentials credentials = get2faCredentials();
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials("secondary", "admin", "adminSecondPassword"));
		primaryAuth(null, null);
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		secondaryAuth("tester", "test");
		primaryAuth(null, null);
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		secondaryAuth("tester", "secondaryPw");
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void getCredentialsShouldGetSecondaryCredentialsIfPrimaryCredentialsAreValid() {
		primaryAuth("tester", "primaryPw");
		TwoFactorAuthenticationCredentials credentials = (TwoFactorAuthenticationCredentials)
				authenticationSession.getAuthenticationContext().getCredentials("2fa");
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		credentials = secondaryAuth("tester", "secondaryPw");
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), notNullValue());
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), nullValue());
	}

	@Test
	public void getCredentialsShouldReturnNullAndRedirectToSecondaryLoginIfSecondaryCredentialsMissing() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThat(credentials, nullValue());
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/secondaryLogin"));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryCredentialsAreMissing() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
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
	public void shouldResetCredentialsIfAuthenticationFails() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "test"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void shouldAuthenticateIfPrimarySucceedsAndSecondaryNotConfigured() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "admin", "adminPassword"
		));
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
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "admin", "adminPassword"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "admin", "adminSecondPassword"
		));
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("primary"));
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
	public void shouldGetPrimaryAuthenticationSchemeFromCredentialsIfConfigured() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "admin", "adminPassword"
		));
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme(credentials).getSchemeId(), equalTo("secondary"));
	}

	@Test
	public void shouldGetPrimaryAuthenticationSchemeFromDefault() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme(credentials).getSchemeId(), equalTo("primary"));
	}

	@Test
	public void shouldThrowExceptionIfNoDefaultPrimaryAuthenticationSchemeConfigured() {
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.primaryOptions", "");
		authenticationScheme = (TwoFactorAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.getPrimaryAuthenticationScheme(credentials));
	}

	@Test
	public void shouldGetSecondaryAuthenticationScheme() {
		TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials("2fa");
		credentials.setPrimaryCredentials(new PrimaryAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new PrimaryAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticationScheme.getSecondaryAuthenticationScheme(authenticated.getUser()).getSchemeId(), equalTo("secondary"));
	}

	@Test
	public void shouldGetCredentialsFromContext() {
		AuthenticationContext ctx = authenticationSession.getAuthenticationContext();
		TwoFactorAuthenticationCredentials c1 = authenticationScheme.getCredentialsFromContext(ctx);
		assertThat(c1.getClass(), equalTo(TwoFactorAuthenticationCredentials.class));
		TwoFactorAuthenticationCredentials c2 = authenticationScheme.getCredentialsFromContext(ctx);
		assertThat(c1, equalTo(c2));
	}

	@Test
	public void shouldParseOptions() {
		List<String> options = authenticationScheme.parseOptions("one,two,three");
		assertThat(options.size(), equalTo(3));
		assertThat(options.get(0), equalTo("one"));
		assertThat(options.get(1), equalTo("two"));
		assertThat(options.get(2), equalTo("three"));
	}

	protected void assertCredentialsEmpty(TwoFactorAuthenticationCredentials creds) {
		assertThat(creds, notNullValue());
		assertThat(creds.getPrimaryCredentials(), nullValue());
		assertThat(creds.getSecondaryCredentials(), nullValue());
		assertThat(creds.getAuthenticationScheme(), equalTo("2fa"));
		assertThat(creds.getClientName(), nullValue());
	}
}
