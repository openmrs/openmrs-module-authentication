package org.openmrs.module.authentication.web.scheme;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;
import org.openmrs.module.authentication.web.BaseWebAuthenticationTest;
import org.openmrs.module.authentication.web.credentials.MultiFactorAuthenticationCredentials;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MultiFactorAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MultiFactorAuthenticationScheme authenticationScheme;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "mfa");
		AuthenticationConfig.setProperty("authentication.scheme.mfa.type", MultiFactorAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.mfa.config.primaryOptions", "primary");
		AuthenticationConfig.setProperty("authentication.scheme.mfa.config.secondaryOptions", "secondary");
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
		authenticationSession = new MockAuthenticationSession(request);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MultiFactorAuthenticationScheme.class));
		authenticationScheme = (MultiFactorAuthenticationScheme) scheme;
	}

	@Test
	public void shouldConfigureFromRuntimeProperties() {
		assertThat(authenticationScheme.getSchemeId(), equalTo("mfa"));
		assertThat(authenticationScheme.getPrimaryOptions().size(), equalTo(1));
		assertThat(authenticationScheme.getPrimaryOptions().get(0), equalTo("primary"));
		assertThat(authenticationScheme.getSecondaryOptions().size(), equalTo(1));
		assertThat(authenticationScheme.getSecondaryOptions().get(0), equalTo("secondary"));
	}

	@Test
	public void getCredentialsShouldReturnEmptyIfNoAuthentication() {
		assertCredentialsEmpty();
	}

	@Test
	public void getCredentialsShouldReturnValidPrimaryCredentialsFromSession() {
		getCredentials();
		assertCredentialsEmpty();
		request.setParameter("uname", "admin");
		request.setParameter("pw", "adminPassword");
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		assertThat(authenticationSession.getAuthenticationContext().getCredentials("primary"), notNullValue());
	}

	@Test
	public void getCredentialsShouldGetValidPrimaryCredentialsFromSessionIfAlreadyAuthenticated() {
		getCredentials();
		assertCredentialsEmpty();
		request.setParameter("uname", "admin");
		request.setParameter("pw", "adminPassword");
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		assertThat(authenticationSession.getAuthenticationContext().getCredentials("primary"), notNullValue());
	}

	@Test
	public void getCredentialsShouldNullifyPrimaryCredentialsIfInvalid() {
		getCredentials();
		assertCredentialsEmpty();
		request.setParameter("uname", "admin");
		request.setParameter("pw", "test");
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		assertThat(authenticationSession.getAuthenticationContext().getCredentials("primary"), nullValue());
	}

	@Test
	public void getCredentialsShouldLogEventIfPrimaryAuthenticationFails() {
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials("primary", "admin", "test"));
		getCredentials();
		assertLastLogContains("marker=PRIMARY_AUTHENTICATION_FAILED");
	}

	@Test
	public void getCredentialsShouldNotGetSecondaryCredentialsUnlessPrimaryCredentialsAreValid() {
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials("secondary", "admin", "adminSecondPassword"));
		credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		request.setParameter("uname", "tester");
		request.setParameter("pw", "test");
		credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		request.setParameter("uname2", "tester");
		request.setParameter("pw2", "secondaryPw");
		credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void getCredentialsShouldGetSecondaryCredentialsIfPrimaryCredentialsAreValid() {
		getCredentials();
		request.setParameter("uname", "tester");
		request.setParameter("pw", "primaryPw");
		MultiFactorAuthenticationCredentials credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
		request.setParameter("uname2", "tester");
		request.setParameter("pw2", "secondaryPw");
		credentials = getCredentials();
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), notNullValue());
	}

	@Test
	public void getChallengeUrlShouldReturnNullIfOnlyPrimaryCredentialsRequiredForUser() {
		request.setParameter("uname", "admin");
		request.setParameter("pw", "adminPassword");
		getCredentials();
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), nullValue());
	}

	@Test
	public void getChallengeUrlShouldReturnNullIfBothPrimaryAndSecondaryCredentialsAreFound() {
		request.setParameter("uname", "tester");
		request.setParameter("pw", "primaryPw");
		request.setParameter("uname2", "tester");
		request.setParameter("pw2", "secondaryPw");
		getCredentials();
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), nullValue());
	}

	@Test
	public void getChallengeUrlShouldReturnPrimaryChallengeUrlIfPrimaryCredentialsMissing() {
		getCredentials();
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/primaryLogin"));
	}

	@Test
	public void getChallengeUrlShouldReturnSecondarChallengeUrlIfSecondaryCredentialsMissing() {
		request.setParameter("uname", "tester");
		request.setParameter("pw", "primaryPw");
		getCredentials();
		assertThat(authenticationScheme.getChallengeUrl(authenticationSession), equalTo("/secondaryLogin"));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryCredentialsAreMissing() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimaryAuthenticationFails() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "test"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetCredentialsIfAuthenticationFails() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "test"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(credentials.getPrimaryCredentials(), nullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void shouldAuthenticateIfPrimarySucceedsAndSecondaryNotConfigured() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "admin", "adminPassword"
		));
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryMissing() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfPrimarySucceedsAndSecondaryFails() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldResetSecondaryCredentialsIfSecondaryAuthenticationFails() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "test"
		));
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
		assertThat(credentials.getPrimaryCredentials(), notNullValue());
		assertThat(credentials.getSecondaryCredentials(), nullValue());
	}

	@Test
	public void shouldAuthenticateWithValidCredentials() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "admin", "adminPassword"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "admin", "adminSecondPassword"
		));
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticated, notNullValue());
		assertThat(authenticated.getAuthenticationScheme(), equalTo("primary"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldFailToAuthenticateWithInvalidCredentials() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(credentials));
	}

	@Test
	public void shouldFailToAuthenticateIfCredentialsAreIncorrectType() {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "adminPassword");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.authenticate(creds));
	}

	@Test
	public void shouldGetPrimaryAuthenticationSchemeFromCredentialsIfConfigured() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "admin", "adminPassword"
		));
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme(credentials).getSchemeId(), equalTo("secondary"));
	}

	@Test
	public void shouldGetPrimaryAuthenticationSchemeFromDefault() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		assertThat(authenticationScheme.getPrimaryAuthenticationScheme(credentials).getSchemeId(), equalTo("primary"));
	}

	@Test
	public void shouldThrowExceptionIfNoDefaultPrimaryAuthenticationSchemeConfigured() {
		AuthenticationConfig.setProperty("authentication.scheme.mfa.config.primaryOptions", "");
		authenticationScheme = (MultiFactorAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		assertThrows(ContextAuthenticationException.class, () -> authenticationScheme.getPrimaryAuthenticationScheme(credentials));
	}

	@Test
	public void shouldGetSecondaryAuthenticationScheme() {
		MultiFactorAuthenticationCredentials credentials = new MultiFactorAuthenticationCredentials("mfa");
		credentials.setPrimaryCredentials(new BasicAuthenticationCredentials(
				"primary", "tester", "primaryPw"
		));
		credentials.setSecondaryCredentials(new BasicAuthenticationCredentials(
				"secondary", "tester", "secondaryPw"
		));
		Authenticated authenticated = authenticationScheme.authenticate(credentials);
		assertThat(authenticationScheme.getSecondaryAuthenticationScheme(authenticated.getUser()).getSchemeId(), equalTo("secondary"));
	}

	@Test
	public void shouldGetCredentialsFromContext() {
		AuthenticationContext ctx = authenticationSession.getAuthenticationContext();
		MultiFactorAuthenticationCredentials c1 = authenticationScheme.getCredentialsFromContext(ctx);
		assertThat(c1.getClass(), equalTo(MultiFactorAuthenticationCredentials.class));
		MultiFactorAuthenticationCredentials c2 = authenticationScheme.getCredentialsFromContext(ctx);
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

	protected MultiFactorAuthenticationCredentials getCredentials() {
		return (MultiFactorAuthenticationCredentials) authenticationScheme.getCredentials(authenticationSession);
	}

	protected void assertCredentialsEmpty() {
		MultiFactorAuthenticationCredentials creds = getCredentials();
		assertThat(creds, notNullValue());
		assertThat(creds.getPrimaryCredentials(), nullValue());
		assertThat(creds.getSecondaryCredentials(), nullValue());
		assertThat(creds.getAuthenticationScheme(), equalTo("mfa"));
		assertThat(creds.getClientName(), nullValue());
	}
}
