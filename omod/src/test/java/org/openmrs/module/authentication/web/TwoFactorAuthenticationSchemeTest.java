package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.openmrs.module.authentication.AuthenticationEvent.AUTHENTICATION_FAILED;

public class TwoFactorAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	TwoFactorAuthenticationScheme authenticationScheme;
	UserLogin userLogin;

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
		userLogin = authenticationSession.getUserLogin();
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(TwoFactorAuthenticationScheme.class));
		authenticationScheme = (TwoFactorAuthenticationScheme) scheme;
		UserLoginTracker.setLoginOnThread(userLogin);
	}

	@AfterEach
	@Override
	public void teardown() {
		UserLoginTracker.removeLoginFromThread();
		super.teardown();
	}

	protected AuthenticationCredentials primaryAuth(String username, String password) {
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

	protected AuthenticationCredentials secondaryAuth(String username, String password) {
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
		return authenticationScheme.getCredentials(authenticationSession);
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
		AuthenticationCredentials credentials = primaryAuth(null, null);
		assertThat(credentials, nullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertThat(userLogin.getValidatedCredentials(), empty());
	}

	@Test
	public void getCredentialsShouldReturnCredentialsIfNoSecondaryAuthenticationRequired() {
		AuthenticationCredentials credentials = primaryAuth("admin", "adminPassword");
		assertThat(credentials, notNullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), containsInAnyOrder("2fa"));
		assertThat(userLogin.getValidatedCredentials(), containsInAnyOrder("primary"));
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), nullValue());
	}

	@Test
	public void getCredentialsShouldNullifyPrimaryCredentialsIfInvalid() {
		AuthenticationCredentials credentials = primaryAuth("admin", "test");
		assertThat(credentials, nullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertThat(userLogin.getValidatedCredentials(), empty());
	}

	@Test
	public void getCredentialsShouldLogEventIfPrimaryAuthenticationFails() {
		primaryAuth("admin", "test");
		assertLoggedEvent(userLogin, AUTHENTICATION_FAILED, "primary");
	}

	@Test
	public void getCredentialsShouldGetSecondaryCredentialsIfPrimaryCredentialsAreValid() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThat(credentials, nullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertThat(userLogin.getValidatedCredentials(), containsInAnyOrder("primary"));
		credentials = secondaryAuth("tester", "secondaryPw");
		assertThat(credentials, notNullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), containsInAnyOrder("2fa"));
		assertValidatedCredentials("primary", "secondary");
	}

	@Test
	public void getCredentialsShouldReturnNullIfSecondaryCredentialsMissing() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThat(credentials, nullValue());
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertValidatedCredentials("primary");
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryCredentialsAreMissing() {
		AuthenticationCredentials credentials = primaryAuth(null, null);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryAuthenticationFails() {
		AuthenticationCredentials credentials = secondaryAuth("tester", "secondaryPw");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetPrimaryCredentialsIfAuthenticationFails() {
		primaryAuth("tester", "test");
		AuthenticationCredentials credentials = secondaryAuth("tester", "secondaryPw");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertThat(userLogin.getValidatedCredentials(), empty());
	}

	@Test
	public void shouldAuthenticateIfPrimarySucceedsAndSecondaryNotConfigured() {
		AuthenticationCredentials credentials = primaryAuth("admin", "adminPassword");
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryMissing() {
		AuthenticationCredentials credentials = primaryAuth("tester", "primaryPw");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryFails() {
		primaryAuth("tester", "primaryPw");
		AuthenticationCredentials credentials = primaryAuth("tester", "test");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetSecondaryCredentialsIfSecondaryAuthenticationFails() {
		primaryAuth("tester", "primaryPw");
		AuthenticationCredentials credentials = secondaryAuth("tester", "test");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(userLogin.getUnvalidatedCredentials(), empty());
		assertValidatedCredentials("primary");
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
		AuthenticationCredentials credentials = primaryAuth(null, null);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}

	@Test
	public void shouldGetPrimaryAuthenticationSchemeFromDefault() {
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme().getSchemeId(), equalTo("primary"));
	}

	@Test
	public void shouldThrowExceptionIfNoDefaultPrimaryAuthenticationSchemeConfigured() {
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.primaryOptions", "");
		authenticationScheme = (TwoFactorAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.getPrimaryAuthenticationScheme());
	}

	@Test
	public void shouldGetSecondaryAuthenticationScheme() {
		primaryAuth("tester", "primaryPw");
		User u = authenticationSession.getUserLogin().getUser();
		WebAuthenticationScheme secondaryScheme = authenticationScheme.getSecondaryAuthenticationScheme(u);
		assertThat(secondaryScheme.getSchemeId(), equalTo("secondary"));
	}

	protected void assertValidatedCredentials(String... schemeIds) {
		assertThat(userLogin.getValidatedCredentials().size(), equalTo(schemeIds.length));
		for (String credential : schemeIds) {
			assertThat(userLogin.isCredentialValidated(credential), equalTo(true));
		}
	}

	protected void assertLoggedEvent(UserLogin userLogin, String event, String schemeId) {
		assertThat(userLogin.containsEvent(event), equalTo(true));
		assertLastLogContains("event=" + event);
		assertLastLogContains("loginId=" + this.userLogin.getLoginId());
		assertLastLogContains("userId=" + this.userLogin.getUserId());
		assertLastLogContains("username=" + this.userLogin.getUsername());
		assertLastLogContains("schemeId=" + schemeId);
	}
}
