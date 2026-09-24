/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.integration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationEvent;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.web.AuthenticationFilter;
import org.openmrs.module.authentication.web.AuthenticationSession;
import org.openmrs.module.authentication.web.BasicWebAuthenticationScheme;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;
import org.openmrs.module.authentication.web.mocks.MockTotpAuthenticationScheme;
import org.openmrs.util.Security;
import org.openmrs.web.test.jupiter.BaseModuleWebContextSensitiveTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TwoFactorAuthenticationSchemeIntegrationTest extends BaseModuleWebContextSensitiveTest {

	private TwoFactorAuthenticationScheme scheme;

	@BeforeEach
	void setUp() {
		scheme = new TwoFactorAuthenticationScheme();
	}

	@Nested
	@DisplayName("addSecondaryAuthenticationSchemeForUser")
	class AddSecondaryAuthenticationSchemeForUser {

		@Test
		@DisplayName("should save the scheme to the database")
		void shouldSaveSchemeToDatabase() {
			User user = Context.getUserService().getUser(1);
			user.getUserProperties().size(); // initialise the lazy collection before detaching
			Context.evictFromSession(user);

			scheme.addSecondaryAuthenticationSchemeForUser(user, "totp");

			Context.flushSession();
			Context.clearSession();

			User savedUser = Context.getUserService().getUser(1);
			String savedProperty = savedUser.getUserProperty(TwoFactorAuthenticationScheme.USER_PROPERTY_SECONDARY_TYPE);
			assertEquals("totp", savedProperty);
		}
	}

	@Nested
	@DisplayName("setSecondaryAuthenticationSchemeIdsForUser")
	class SetSecondaryAuthenticationSchemeIdsForUser {

		@Test
		@DisplayName("should save the schemes to the database")
		void shouldSaveSchemesToDatabase() {
			User user = Context.getUserService().getUser(1);
			user.getUserProperties().size(); // initialise the lazy collection before detaching
			Context.evictFromSession(user);

			scheme.setSecondaryAuthenticationSchemeIdsForUser(user, Collections.singletonList("totp"));

			Context.flushSession();
			Context.clearSession();

			User savedUser = Context.getUserService().getUser(1);
			String savedProperty = savedUser.getUserProperty(TwoFactorAuthenticationScheme.USER_PROPERTY_SECONDARY_TYPE);
			assertEquals("totp", savedProperty);
		}
	}


	/**
	 * Drives {@link AuthenticationFilter} over a sequence of real requests and asserts on the
	 * {@link UserLogin} that the filter carries across them.
	 * <p>
	 * Credentials are submitted the way the O3 actually submits them: a GET of /ws/rest/v1/session
	 * carrying the factor in a header - Basic for the primary factor, X-Totp-Code for the second.  That
	 * endpoint has its own branch in the filter, and /ws/**&#47;* is a non-redirect url by default, so an
	 * unsatisfied login is answered with a Location header rather than a 3xx to a login page.
	 * <p>
	 * The {@link UserLogin} is the state these tests care about most.  Challenge urls are derived from it,
	 * so asserting only on those hides which part of the login state a change actually broke.
	 */
	@Nested
	@DisplayName("authenticationWebFlowIntegration")
	class AuthenticationWebFlowIntegration {

		private static final String SESSION_URL = "/ws/rest/v1/session";

		private static final String PROTECTED_RESOURCE_URL = "/ws/rest/v1/patient";

		private static final String PRIMARY_LOGIN_PAGE = "/spa/login";

		private static final String SECONDARY_LOGIN_PAGE = "/spa/two-factor-auth";

		private static final String TOTP_CODE_HEADER = "X-Totp-Code";

		private static final String VALID_CODE = "valid_secret_code";

		private User user;

		private Properties originalProperties;

		private AuthenticationFilter filter;

		private MockHttpSession httpSession;

		@BeforeEach
		void setUpWebFlow() throws Exception {
			user = Context.getUserService().getUserByUsername("admin");
			scheme.addSecondaryAuthenticationSchemeForUser(user, "totp");

			// TotpAuthenticationScheme expects the secret to be encrypted in the database.
			// When validating, it will call Security.decrypt() on this property.
			user.setUserProperty("authentication.totp.secret", Security.encrypt(VALID_CODE));
			Context.getUserService().saveUser(user);

			originalProperties = Context.getRuntimeProperties();
			// Reset any configuration an earlier test left behind, so that the authenticated session this
			// test starts with is not resolved through some other test's authentication scheme.
			AuthenticationConfig.setConfig(originalProperties);
			filter = new AuthenticationFilter();
			filter.init(new MockFilterConfig());
			httpSession = new MockHttpSession();
		}

		@AfterEach
		void tearDownWebFlow() {
			// AuthenticationConfig and the runtime properties are global state.  Without this they leak into
			// every test that runs afterwards, which shows up as unrelated failures elsewhere in the build.
			AuthenticationConfig.setConfig(originalProperties);
			Context.setRuntimeProperties(originalProperties);
		}

		@Test
		@DisplayName("should keep user on 2FA page after a wrong TOTP code and allow a successful retry")
		void shouldKeepUserOn2faPageAfterWrongCodeAndAllowRetry() throws Exception {
			applyConfig(twoFactorProperties());

			MockHttpServletResponse primary = submit(primaryRequest("admin", "test"));
			assertEquals(SECONDARY_LOGIN_PAGE, primary.getHeader("Location"),
					"Should point the client at the 2FA page once primary authentication succeeds");
			assertEquals(user, userLogin().getUser(), "Primary success should establish the candidate user");
			assertTrue(userLogin().getValidatedCredentials().contains("basic"),
					"Primary scheme should be recorded as validated");
			assertFalse(userLogin().isUserAuthenticated(), "Primary alone must not authenticate the user");

			MockHttpServletResponse wrongCode = submit(secondaryRequest("a_wrong_code"));
			assertEquals(SECONDARY_LOGIN_PAGE, wrongCode.getHeader("Location"),
					"Should point the client back at the 2FA page when the code is wrong");
			assertEquals(user, userLogin().getUser(), "A wrong second factor must not drop the candidate user");
			assertTrue(userLogin().getValidatedCredentials().contains("basic"),
					"A wrong second factor must not discard the validated primary factor");
			assertFalse(userLogin().getValidatedCredentials().contains("totp"),
					"A wrong second factor must not be recorded as validated");
			assertTrue(userLogin().containsEvent(AuthenticationEvent.AUTHENTICATION_FAILED),
					"The failed second factor should be recorded on the login");
			assertFalse(Context.isAuthenticated(), "User should not be fully authenticated yet");

			submit(secondaryRequest(VALID_CODE));
			assertTrue(Context.isAuthenticated(), "User should be fully authenticated");
			assertEquals(user, Context.getAuthenticatedUser(), "Authenticated user should match candidate");
			assertTrue(userLogin().getValidatedCredentials().contains("totp"),
					"Second factor should be recorded as validated");
			assertTrue(userLogin().containsEvent(AuthenticationEvent.LOGIN_SUCCEEDED),
					"A successful login should be recorded on the login");
		}

		/**
		 * Regression test for AUT-31.
		 * <p>
		 * A client logs in at /ws/rest/v1/session with Basic credentials.  {@link AuthenticationFilter}
		 * validates the primary factor, sees the second factor is still outstanding, and answers with the
		 * 2FA page as the challenge url.  The request then continues down the chain to the webservices.rest
		 * AuthorizationFilter, which sees the same Authorization header and calls
		 * {@code Context.authenticate(username, password)} itself.  Those are plain
		 * {@code UsernamePasswordCredentials}, which the two-factor scheme rejects outright, so core
		 * notifies every {@code UserSessionListener} with LOGIN/FAIL and {@code UserLogin#loginFailed()}
		 * runs.
		 * <p>
		 * Before AUT-31 that cleared the candidate user unconditionally, so the very response that pointed
		 * the client at the 2FA page had already discarded the user it needs, and the next call to the
		 * session endpoint sent them back to the primary login page.
		 * <p>
		 * No second factor is submitted here: the whole point is that the login is still half finished.
		 * This also reaches {@code loginFailed()} without going through {@code authenticationFailed}, so it
		 * exercises the AUT-31 guard on its own.
		 */
		@Test
		@DisplayName("should retain the candidate user while the second factor is still outstanding")
		void shouldRetainCandidateUserWhileSecondFactorIsOutstanding() throws Exception {
			applyConfig(twoFactorProperties());

			MockHttpServletResponse first = submit(primaryRequest("admin", "test"));

			assertEquals(SECONDARY_LOGIN_PAGE, first.getHeader("Location"),
					"The client should be pointed at the 2FA page");
			assertTrue(userLogin().containsEvent(AuthenticationEvent.LOGIN_FAILED),
					"The downstream REST authentication should really have registered a failed login, "
							+ "otherwise this test is not exercising loginFailed() at all");
			assertEquals(user, userLogin().getUser(),
					"That failed login must not drop the candidate user midway through a 2FA login");
			assertEquals("admin", userLogin().getUsername(),
					"That failed login must not drop the username midway through a 2FA login");
			assertTrue(userLogin().getValidatedCredentials().contains("basic"),
					"The validated primary factor must survive");
			assertFalse(Context.isAuthenticated(), "The user must not be authenticated on one factor");

			// The candidate user drives the challenge url, so losing it sends the client back to the
			// primary login page instead of the 2FA page.  This is the redirect regression AUT-31 describes.
			MockHttpServletResponse second = submit(sessionRequest());

			assertEquals(SECONDARY_LOGIN_PAGE, second.getHeader("Location"),
					"A second call should still ask for the outstanding factor, not restart primary login");
			assertEquals(user, userLogin().getUser(), "The candidate user should still be on the login");
		}

		/**
		 * The other half of the AUT-31 guard.  When nothing has been validated yet there is no candidate to
		 * protect, so a failed login must still clear the login state.
		 * <p>
		 * This asserts on the username rather than the user because {@code UserLogin#authenticationFailed}
		 * also clears the user.  Only {@code loginFailed()} clears the username, so this is what actually
		 * pins the guard's condition: invert it and this test fails.
		 */
		@Test
		@DisplayName("should clear login state when primary authentication fails with nothing yet validated")
		void shouldClearLoginStateWhenPrimaryAuthenticationFails() throws Exception {
			applyConfig(basicOnlyProperties());

			MockHttpServletResponse response = submit(primaryRequest("admin", "a_wrong_password"));

			assertEquals(401, response.getStatus(), "A rejected login should be answered with a 401");
			assertEquals(PRIMARY_LOGIN_PAGE, response.getHeader("Location"),
					"The client should be pointed back at the primary login page");
			assertNull(userLogin().getUser(), "A failed primary login should leave no candidate user");
			assertNull(userLogin().getUsername(), "A failed primary login should leave no username");
			assertTrue(userLogin().getValidatedCredentials().isEmpty(), "Nothing should be recorded as validated");
			assertTrue(userLogin().containsEvent(AuthenticationEvent.LOGIN_FAILED),
					"The failed login should be recorded on the login");
			assertFalse(Context.isAuthenticated(), "The user must not be authenticated");
		}

		/**
		 * The session endpoint is whitelisted and gets its own branch in the filter: rather than failing the
		 * request, it advertises where the client should go to log in.
		 */
		@Test
		@DisplayName("should advertise the challenge url on the session endpoint when no credentials are sent")
		void shouldAdvertiseChallengeUrlOnSessionEndpointWithoutCredentials() throws Exception {
			applyConfig(twoFactorProperties());

			MockFilterChain chain = new MockFilterChain();
			MockHttpServletResponse response = submit(sessionRequest(), chain);

			assertEquals(200, response.getStatus(), "Asking for the session without credentials is not an error");
			assertEquals(PRIMARY_LOGIN_PAGE, response.getHeader("Location"),
					"The client should be told where to log in");
			assertNotNull(chain.getRequest(),
					"The session endpoint should still be served so the client can read the session state");
		}

		@Test
		@DisplayName("should surface an error message on the 2FA page and clear it on success")
		void shouldSurfaceErrorMessageAndClearItOnSuccess() throws Exception {
			applyConfig(twoFactorProperties());

			submit(primaryRequest("admin", "test"));
			assertNull(errorMessage(), "A successful primary factor should leave no error message");

			submit(secondaryRequest("a_wrong_code"));
			assertNotNull(errorMessage(),
					"The 2FA page needs an error message to render, otherwise the wrong code fails silently");

			submit(secondaryRequest(VALID_CODE));
			assertNull(errorMessage(), "A successful login should clear the previous error message");
		}

		/**
		 * {@link AuthenticationSession#regenerateHttpSession()} replaces the HTTP session on success to guard
		 * against session fixation.  MockHttpServletRequest honours this, but only for the request that
		 * triggered it, so the new session has to be read back off that request rather than from the session
		 * the test handed in.
		 */
		@Test
		@DisplayName("should regenerate the http session on successful login and carry the login across")
		void shouldRegenerateHttpSessionOnSuccess() throws Exception {
			applyConfig(twoFactorProperties());

			String originalSessionId = httpSession.getId();
			submit(primaryRequest("admin", "test"));
			assertEquals(originalSessionId, httpSession.getId(),
					"The session should not be regenerated before the login completes");

			MockHttpServletRequest request = secondaryRequest(VALID_CODE);
			submit(request);

			HttpSession regenerated = request.getSession(false);
			assertNotNull(regenerated, "A new session should have been created");
			assertNotEquals(originalSessionId, regenerated.getId(),
					"The session id should change on login to guard against session fixation");
			assertNotNull(regenerated.getAttribute(AuthenticationSession.AUTHENTICATION_USER_LOGIN),
					"The UserLogin should be carried over to the regenerated session");
		}

		@Test
		@DisplayName("should block a protected resource until both factors are satisfied")
		void shouldBlockProtectedResourceUntilAuthenticated() throws Exception {
			applyConfig(twoFactorProperties());

			MockFilterChain blocked = new MockFilterChain();
			MockHttpServletResponse denied = submit(protectedResourceRequest(), blocked);
			assertEquals(401, denied.getStatus(), "A protected resource should be refused before logging in");
			assertNull(blocked.getRequest(), "A refused request must not reach the rest of the chain");

			submit(primaryRequest("admin", "test"));
			submit(secondaryRequest(VALID_CODE));

			MockFilterChain allowed = new MockFilterChain();
			MockHttpServletResponse served = submit(protectedResourceRequest(), allowed);
			assertEquals(200, served.getStatus(), "The resource should be served once both factors are satisfied");
			assertNotNull(allowed.getRequest(), "The request should reach the rest of the chain");
		}

		@Test
		@DisplayName("should redirect to the requested page after a successful login")
		void shouldRedirectToRequestedPageAfterSuccessfulLogin() throws Exception {
			applyConfig(twoFactorProperties());

			submit(primaryRequest("admin", "test"));

			MockHttpServletRequest request = secondaryRequest(VALID_CODE);
			request.setParameter("redirect", "/patientDashboard.htm?patientId=2");
			MockHttpServletResponse response = submit(request);

			assertEquals("/patientDashboard.htm?patientId=2", response.getRedirectedUrl(),
					"A successful login should return the user to the page they asked for");
		}

		private Properties twoFactorProperties() {
			Properties properties = new Properties();
			properties.putAll(originalProperties);
			properties.setProperty(AuthenticationConfig.SCHEME, "2fa");
			properties.setProperty("authentication.scheme.2fa.type", TwoFactorAuthenticationScheme.class.getName());
			properties.setProperty("authentication.scheme.2fa.config.primaryOptions", "basic");
			properties.setProperty("authentication.scheme.2fa.config.secondaryOptions", "totp");

			properties.setProperty("authentication.scheme.basic.type", BasicWebAuthenticationScheme.class.getName());
			properties.setProperty("authentication.scheme.basic.config.loginPage", PRIMARY_LOGIN_PAGE);

			properties.setProperty("authentication.scheme.totp.type", MockTotpAuthenticationScheme.class.getName());
			properties.setProperty("authentication.scheme.totp.config.loginPage", SECONDARY_LOGIN_PAGE);
			properties.setProperty("authentication.scheme.totp.config.codeHeader", TOTP_CODE_HEADER);
			return properties;
		}

		private Properties basicOnlyProperties() {
			Properties properties = new Properties();
			properties.putAll(originalProperties);
			properties.setProperty(AuthenticationConfig.SCHEME, "basic");
			properties.setProperty("authentication.scheme.basic.type", BasicWebAuthenticationScheme.class.getName());
			properties.setProperty("authentication.scheme.basic.config.loginPage", PRIMARY_LOGIN_PAGE);
			return properties;
		}

		/**
		 * Installs the configuration under test and drops the authenticated session that
		 * BaseModuleWebContextSensitiveTest sets up for each test, so that AuthenticationFilter actually
		 * intercepts the requests below instead of waving them through as already authenticated.
		 * <p>
		 * Anything a test needs to write to the database has to happen before this call, while there is
		 * still an authenticated user.
		 */
		private void applyConfig(Properties properties) {
			Context.logout();
			AuthenticationConfig.setConfig(properties);
			Context.setRuntimeProperties(properties);
		}

		/**
		 * @return a bare GET of the session endpoint, carrying no credentials
		 */
		private MockHttpServletRequest sessionRequest() {
			MockHttpServletRequest request = new MockHttpServletRequest("GET", SESSION_URL);
			request.setSession(httpSession);
			return request;
		}

		/**
		 * @return a GET of the session endpoint submitting the primary factor as a Basic Authorization header
		 */
		private MockHttpServletRequest primaryRequest(String username, String password) {
			MockHttpServletRequest request = sessionRequest();
			String token = username + ":" + password;
			request.addHeader("Authorization",
					"Basic " + Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8)));
			return request;
		}

		/**
		 * @return a GET of the session endpoint submitting the second factor as an X-Totp-Code header
		 */
		private MockHttpServletRequest secondaryRequest(String code) {
			MockHttpServletRequest request = sessionRequest();
			request.addHeader(TOTP_CODE_HEADER, code);
			return request;
		}

		/**
		 * @return a GET of a protected resource: not whitelisted, and not the session endpoint, so the filter
		 * refuses it outright until the user is authenticated
		 */
		private MockHttpServletRequest protectedResourceRequest() {
			MockHttpServletRequest request = new MockHttpServletRequest("GET", PROTECTED_RESOURCE_URL);
			request.setSession(httpSession);
			return request;
		}

		/**
		 * Every /ws/rest request also passes through the webservices.rest AuthorizationFilter, which reads
		 * the same Basic Authorization header and calls Context.authenticate itself, swallowing any
		 * failure.  That second authentication attempt is what makes a half-finished two-factor login
		 * register a failed login, so the tests here are only realistic with it in the chain.
		 * <p>
		 * The real filter is not usable here - it initialises RestConstants, which reads a global property
		 * and needs the REST module started - so this mirrors the part that matters.
		 */
		private MockFilterChain restChain() {
			Filter restAuthorizationFilter = new Filter() {

				@Override
				public void init(FilterConfig filterConfig) {
				}

				@Override
				public void destroy() {
				}

				@Override
				public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
						throws IOException, ServletException {
					String basicAuth = ((HttpServletRequest) request).getHeader("Authorization");
					if (!Context.isAuthenticated() && basicAuth != null && basicAuth.startsWith("Basic")) {
						try {
							String decoded = new String(Base64.getDecoder().decode(basicAuth.substring(6)),
									StandardCharsets.UTF_8);
							String[] userAndPass = decoded.split(":");
							Context.authenticate(userAndPass[0], userAndPass[1]);
						}
						catch (Exception e) {
							// AuthorizationFilter never stops execution when authentication fails
						}
					}
					chain.doFilter(request, response);
				}
			};
			HttpServlet endOfChain = new HttpServlet() {

				@Override
				protected void service(HttpServletRequest request, HttpServletResponse response) {
				}
			};
			return new MockFilterChain(endOfChain, restAuthorizationFilter);
		}

		private MockHttpServletResponse submit(MockHttpServletRequest request) throws Exception {
			return submit(request, restChain());
		}

		private MockHttpServletResponse submit(MockHttpServletRequest request, MockFilterChain chain) throws Exception {
			MockHttpServletResponse response = new MockHttpServletResponse();
			filter.doFilter(request, response, chain);

			// A successful login regenerates the http session to guard against session fixation, which
			// invalidates the one handed in.  Follow the replacement the way a client follows the new
			// session cookie, so later requests and assertions read the session the filter is now using.
			HttpSession current = request.getSession(false);
			if (current instanceof MockHttpSession && current != httpSession) {
				httpSession = (MockHttpSession) current;
			}
			return response;
		}

		/**
		 * @return the UserLogin the filter is carrying across requests, read back off the http session the
		 * same way the filter reads it
		 */
		private UserLogin userLogin() {
			return (UserLogin) httpSession.getAttribute(AuthenticationSession.AUTHENTICATION_USER_LOGIN);
		}

		private String errorMessage() {
			return (String) httpSession.getAttribute(AuthenticationSession.AUTHENTICATION_ERROR_MESSAGE);
		}
	}
}
