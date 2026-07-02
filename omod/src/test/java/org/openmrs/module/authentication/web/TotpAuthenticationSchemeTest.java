package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.APIAuthenticationException;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.UserContext;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.TestAuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.controller.TwoFactorEnrollmentController;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockTotpAuthenticationScheme;
import org.openmrs.module.webservices.rest.SimpleObject;
import org.openmrs.module.webservices.rest.web.response.ResourceDoesNotSupportOperationException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
	
	@Test
	public void shouldInitiateEnrollmentSuccessfully() {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		SimpleObject result = authenticationScheme.initiateEnrollment(request);
		
		assertThat(result, notNullValue());
		assertThat(result.get("secret"), notNullValue());
		assertThat(result.get("qrCodeUri"), notNullValue());
		
		String sessionSecret = (String) request.getSession().getAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET);
		assertThat(sessionSecret, equalTo(result.get("secret")));
	}
	
	@Test
	public void shouldVerifyEnrollmentSuccessfully() {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		String secret = "OMRS12345678";
		request.getSession().setAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET, secret);
		
		SimpleObject payload = new SimpleObject();
		payload.put("code", secret);
		
		SimpleObject result = authenticationScheme.verifyEnrollment(payload, request);
		assertThat(result, notNullValue());
		assertThat(result.get("isValidCode"), equalTo(true));
		assertThat(request.getSession().getAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET), nullValue());
		
		String savedSecret = candidateUser.getUserProperty(authenticationScheme.getSecretUserPropertyName());
		assertThat(savedSecret, notNullValue());
	}
	
	@Test
	public void shouldThrowExceptionIfUnauthenticatedInInitiateEnrollment() {
		Context.setUserContext(new UserContext(null));
		
		assertThrows(APIAuthenticationException.class, () -> {
			authenticationScheme.initiateEnrollment(request);
		});
	}
	
	@Test
	public void shouldThrowExceptionIfUnauthenticatedInVerifyEnrollment() {
		Context.setUserContext(new UserContext(null));
		
		SimpleObject payload = new SimpleObject();
		payload.put("code", "123456");
		
		assertThrows(APIAuthenticationException.class, () -> {
			authenticationScheme.verifyEnrollment(payload, request);
		});
	}
	
	@Test
	public void shouldThrowExceptionIfCodeIsInvalidInVerifyEnrollment() {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		String secret = "OMRS12345678";
		request.getSession().setAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET, secret);
		
		SimpleObject payload = new SimpleObject();
		payload.put("code", "invalid_code");
		
		assertThrows(IllegalArgumentException.class, () -> {
			authenticationScheme.verifyEnrollment(payload, request);
		});
	}
	
	@Test
	public void shouldThrowExceptionIfNoStashedSecretInVerifyEnrollment() {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		SimpleObject payload = new SimpleObject();
		payload.put("code", "123456");
		
		assertThrows(IllegalArgumentException.class, () -> {
			authenticationScheme.verifyEnrollment(payload, request);
		});
	}
	
	@Test
	public void shouldHandleUnsupportedSchemeInController() {
		AuthenticationConfig.setProperty("authentication.scheme.basic2.type", BasicWebAuthenticationScheme.class.getName());
		setRuntimeProperties(AuthenticationConfig.getConfig());
		
		TwoFactorEnrollmentController controller = new TwoFactorEnrollmentController();
		
		assertThrows(ResourceDoesNotSupportOperationException.class, () -> {
			controller.initiateEnrollment("basic2", request);
		});
	}
	
	@Test
	public void shouldHandleIllegalArgumentExceptionInController() {
		TwoFactorEnrollmentController controller = new TwoFactorEnrollmentController();
		
		IllegalArgumentException exception = new IllegalArgumentException("Invalid code");
		SimpleObject error = controller.handleIllegalArgumentException(exception);
		
		assertThat(error, notNullValue());
		assertThat(error.get("message"), equalTo("Invalid code"));
	}
	
	@Test
	public void shouldThrowExceptionIfCodeIsMissing() {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		String secret = "OMRS12345678";
		request.getSession().setAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET, secret);
		
		SimpleObject payload = new SimpleObject();
		
		assertThrows(IllegalArgumentException.class, () -> {
			authenticationScheme.verifyEnrollment(payload, request);
		});
	}
	
	@Test
	public void shouldVerifyEnrollmentSuccessfulWithNumericCode () {
		Context.setUserContext(new MockUserContext(candidateUser));
		
		String secret = "123456";
		request.getSession().setAttribute(TotpAuthenticationScheme.PENDING_ENROLLMENT_SECRET, secret);
		
		SimpleObject payload = new SimpleObject();
		payload.put("code", 123456);
		
		SimpleObject result = authenticationScheme.verifyEnrollment(payload, request);
		
		assertThat(result, notNullValue());
		assertThat(result.get("isValidCode"), equalTo(true));
	}
	
	private static class MockUserContext extends UserContext {
		private final User user;
		public MockUserContext(User user) {
			super(null);
			this.user = user;
		}
		
		@Override
		public User getAuthenticatedUser() {
			return user;
		}
	}
}
