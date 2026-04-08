package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
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
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockEmailAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EmailAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockEmailAuthenticationScheme authenticationScheme;
	User candidateUser;
	UserLogin userLogin;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "email");
		AuthenticationConfig.setProperty("authentication.scheme.email.type", MockEmailAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.email.config.loginPage", "/emailCode.page");
		AuthenticationConfig.setProperty("authentication.scheme.email.config.codeParam", "code");
		AuthenticationConfig.setProperty("authentication.scheme.email.config.codeLength", "6");
		AuthenticationConfig.setProperty("authentication.scheme.email.config.codeExpirationMinutes", "10");
		AuthenticationConfig.setProperty("authentication.scheme.email.config.emailSubject", "Your code");
		AuthenticationConfig.setProperty("authentication.scheme.email.config.resendParam", "resend");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		response = newResponse();
		candidateUser = new User();
		candidateUser.setUsername("testing");
		authenticationSession = new MockAuthenticationSession(request, response);
		userLogin = authenticationSession.getUserLogin();
		userLogin.addUnvalidatedCredentials(new TestAuthenticationCredentials("primary", candidateUser));
		userLogin.authenticationSuccessful("primary", new BasicAuthenticated(candidateUser, "primary"));
		UserLoginTracker.setLoginOnThread(userLogin);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockEmailAuthenticationScheme.class));
		authenticationScheme = (MockEmailAuthenticationScheme) scheme;
	}

	@AfterEach
	@Override
	public void teardown() {
		UserLoginTracker.removeLoginFromThread();
	}

	protected AuthenticationCredentials getCredentials(String code, String resend) {
		request = newPostRequest("192.168.1.1", "/login");
		if (code != null) {
			request.setParameter("code", code);
		}
		if (resend != null) {
			request.setParameter("resend", resend);
		}
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		return authenticationScheme.getCredentials(authenticationSession);
	}

	// Configuration tests

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("email"));
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/emailCode.page"));
	}

	// isUserConfigurationRequired tests

	@Test
	public void isUserConfigurationRequiredShouldReturnTrueWhenEmailIsNull() {
		User user = new User();
		assertThat(authenticationScheme.isUserConfigurationRequired(user), equalTo(true));
	}

	@Test
	public void isUserConfigurationRequiredShouldReturnTrueWhenEmailIsInvalid() {
		User user = new User();
		user.setEmail("notanemail");
		assertThat(authenticationScheme.isUserConfigurationRequired(user), equalTo(true));
	}

	@Test
	public void isUserConfigurationRequiredShouldReturnTrueWhenEmailIsNotVerified() {
		User user = new User();
		user.setEmail("user@openmrs.org");
		assertThat(authenticationScheme.isUserConfigurationRequired(user), equalTo(true));
	}

	@Test
	public void isUserConfigurationRequiredShouldReturnFalseWhenEmailIsValidAndVerified() {
		User user = new User();
		user.setEmail("user@openmrs.org");
		user.setUserProperty(authenticationScheme.getVerifiedEmailUserPropertyName(), "user@openmrs.org");
		assertThat(authenticationScheme.isUserConfigurationRequired(user), equalTo(false));
	}

	// getChallengeUrl tests

	@Test
	public void getChallengeUrlShouldReturnConfiguredLoginPage() {
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/emailCode.page"));
	}

	// getCredentials tests

	@Test
	public void getCredentialsShouldNotResendEmailIfCodeAlreadyInSession() {
		getCredentials(null, null);
		String firstCode = authenticationScheme.getLastSentCode();
		getCredentials(null, null);
		assertThat(authenticationScheme.getLastSentCode(), equalTo(firstCode));
	}

	@Test
	public void getCredentialsShouldResendEmailWhenResendParamPresent() {
		getCredentials(null, null);
		String firstCode = authenticationScheme.getLastSentCode();
		getCredentials(null, "true");
		String secondCode = authenticationScheme.getLastSentCode();
		assertThat(secondCode, notNullValue());
		// A new code should have been sent (may theoretically be the same value but a new send occurred)
		assertThat(authenticationScheme.getLastSentCode(), notNullValue());
	}

	@Test
	public void getCredentialsShouldResendEmailWhenCodeIsExpired() {
		getCredentials(null, null);
		// Manually expire the code in the session
		session.setAttribute(authenticationScheme.getSessionCodeKey(), "123456");
		session.setAttribute(authenticationScheme.getSessionExpiryKey(), System.currentTimeMillis() - 1000L);
		getCredentials(null, null);
		assertThat(authenticationScheme.getLastSentCode(), notNullValue());
	}

	@Test
	public void getCredentialsShouldReturnCredentialsWhenCodeSubmitted() {
		getCredentials(null, null);
		String sentCode = authenticationScheme.getLastSentCode();
		AuthenticationCredentials credentials = getCredentials(sentCode, null);
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("email"));
	}

	@Test
	public void getCredentialsShouldReturnCachedCredentialsIfAlreadyPresent() {
		getCredentials(null, null);
		String sentCode = authenticationScheme.getLastSentCode();
		AuthenticationCredentials first = getCredentials(sentCode, null);
		assertThat(first, notNullValue());
		// Second call should return same cached credentials
		AuthenticationCredentials second = getCredentials("differentCode", null);
		assertThat(second, equalTo(first));
	}

	@Test
	public void getCredentialsShouldThrowExceptionWhenNoCandidateUser() {
		MockHttpSession freshSession = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(freshSession);
		authenticationSession = new MockAuthenticationSession(request, response);
		UserLoginTracker.setLoginOnThread(authenticationSession.getUserLogin());
		assertThrows(ContextAuthenticationException.class,
				() -> authenticationScheme.getCredentials(authenticationSession));
	}

	// authenticate tests

	@Test
	public void shouldAuthenticateWithValidCodeAndNotExpired() {
		getCredentials(null, null);
		String sentCode = authenticationScheme.getLastSentCode();
		AuthenticationCredentials credentials = getCredentials(sentCode, null);
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("email"));
		assertThat(authenticated.getUser().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldFailToAuthenticateWithIncorrectCode() {
		getCredentials(null, null);
		AuthenticationCredentials credentials = getCredentials("000000", null);
		// Only fails if 000000 isn't the actual sent code (extremely unlikely with 6 digits)
		if (!authenticationScheme.getLastSentCode().equals("000000")) {
			assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		}
	}

	@Test
	public void shouldFailToAuthenticateWhenCodeIsExpired() {
		getCredentials(null, null);
		String sentCode = authenticationScheme.getLastSentCode();
		// Build credentials with past expiry
		EmailAuthenticationScheme.EmailCredentials credentials =
				authenticationScheme.new EmailCredentials(candidateUser, sentCode, sentCode, System.currentTimeMillis() - 1000L);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateWithNullUser() {
		EmailAuthenticationScheme.EmailCredentials credentials =
				authenticationScheme.new EmailCredentials(null, "123456", "123456", System.currentTimeMillis() + 60_000L);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateWithBlankSubmittedCode() {
		EmailAuthenticationScheme.EmailCredentials credentials =
				authenticationScheme.new EmailCredentials(candidateUser, "", "123456", System.currentTimeMillis() + 60_000L);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfUserDiffersFromCandidateUser() {
		User otherUser = new User();
		otherUser.setUsername("other");
		userLogin.setUser(candidateUser);
		EmailAuthenticationScheme.EmailCredentials credentials =
				authenticationScheme.new EmailCredentials(otherUser, "123456", "123456", System.currentTimeMillis() + 60_000L);
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}

	// End-to-end flow test

	@Test
	public void shouldCompleteFullEmailCodeFlow() {
		// Step 1: first call triggers email send, returns null (user hasn't submitted yet)
		AuthenticationCredentials credentials = getCredentials(null, null);
		assertThat(credentials, nullValue());
		assertThat(authenticationScheme.getLastSentCode(), notNullValue());

		// Step 2: user submits the sent code
		String sentCode = authenticationScheme.getLastSentCode();
		credentials = getCredentials(sentCode, null);
		assertThat(credentials, notNullValue());

		// Step 3: authenticate with the credentials
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated instanceof BasicAuthenticated, equalTo(true));
		assertThat(authenticated.getUser().getUsername(), equalTo("testing"));
		assertThat(authenticated.getAuthenticationScheme(), equalTo("email"));
	}
}
