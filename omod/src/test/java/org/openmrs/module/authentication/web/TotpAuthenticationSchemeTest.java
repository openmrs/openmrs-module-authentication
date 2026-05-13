package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.TestAuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockTotpAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class TotpAuthenticationSchemeTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockTotpAuthenticationScheme authenticationScheme;
	User candidateUser;
	UserLogin userLogin;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		AuthenticationConfig.setProperty("authentication.scheme", "totp");
		AuthenticationConfig.setProperty("authentication.scheme.totp.type", MockTotpAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.totp.config.loginPage", "/loginTotp.page");
		AuthenticationConfig.setProperty("authentication.scheme.totp.config.codeParam", "code");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		candidateUser = new User();
		candidateUser.setUsername("testing");
		authenticationSession = new MockAuthenticationSession(request, newResponse());
		userLogin = authenticationSession.getUserLogin();
		userLogin.addUnvalidatedCredentials(new TestAuthenticationCredentials("test", candidateUser));
		userLogin.authenticationSuccessful("test", new BasicAuthenticated(candidateUser, "test"));
		UserLoginTracker.setLoginOnThread(userLogin);
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockTotpAuthenticationScheme.class));
		authenticationScheme = (MockTotpAuthenticationScheme) scheme;
	}

	@AfterEach
	@Override
	public void teardown() {
		UserLoginTracker.removeLoginFromThread();
	}

	private AuthenticationCredentials getCredentials(String paramCode, String headerCode) {
		MockHttpServletRequest req = newPostRequest("192.168.1.1", "/login");
		if (paramCode != null) {
			req.setParameter("code", paramCode);
		}
		if (headerCode != null) {
			req.addHeader("X-Totp-Code", headerCode);
		}
		req.setSession(session);
		return authenticationScheme.getCredentials(new MockAuthenticationSession(req, newResponse()));
	}

	@Test
	public void shouldReturnNullIfNeitherParamNorHeaderPresent() {
		assertThat(getCredentials(null, null), nullValue());
	}

	@Test
	public void shouldGetCredentialsFromRequestParam() {
		AuthenticationCredentials credentials = getCredentials("123456", null);
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("totp"));
	}

	@Test
	public void shouldGetCredentialsFromHeader() {
		AuthenticationCredentials credentials = getCredentials(null, "123456");
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
		assertThat(credentials.getAuthenticationScheme(), equalTo("totp"));
	}

	@Test
	public void shouldPreferParamOverHeader() {
		AuthenticationCredentials credentials = getCredentials("fromParam", "fromHeader");
		assertThat(credentials, notNullValue());
		TotpAuthenticationScheme.TotpCredentials tc = (TotpAuthenticationScheme.TotpCredentials) credentials;
		assertThat(tc.code, equalTo("fromParam"));
	}

	@Test
	public void shouldUseConfiguredHeaderName() {
		AuthenticationConfig.setProperty("authentication.scheme.totp.config.codeHeader", "X-Custom-Otp");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		MockTotpAuthenticationScheme customScheme = (MockTotpAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();

		MockHttpServletRequest req = newPostRequest("192.168.1.1", "/login");
		req.addHeader("X-Custom-Otp", "123456");
		req.setSession(session);
		AuthenticationCredentials credentials = customScheme.getCredentials(new MockAuthenticationSession(req, newResponse()));
		assertThat(credentials, notNullValue());
		assertThat(credentials.getClientName(), equalTo("testing"));
	}
}
