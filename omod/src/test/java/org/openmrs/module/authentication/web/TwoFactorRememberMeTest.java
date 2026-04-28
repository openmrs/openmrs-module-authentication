/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.openmrs.module.authentication.web.mocks.MockTwoFactorAuthenticationScheme;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.http.Cookie;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * Tests for the remember-me bypass behavior of {@link TwoFactorAuthenticationScheme}.
 */
public class TwoFactorRememberMeTest extends BaseWebAuthenticationTest {

	private static final String COOKIE_NAME = "authentication.2fa.rememberMe";

	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockTwoFactorAuthenticationScheme authenticationScheme;
	MockAuthenticationSession authenticationSession;
	UserLogin userLogin;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		MockBasicWebAuthenticationScheme.reset();
		AuthenticationConfig.setProperty("authentication.scheme", "2fa");
		AuthenticationConfig.setProperty("authentication.scheme.2fa.type", MockTwoFactorAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.primaryOptions", "primary");
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.secondaryOptions", "secondary");
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.rememberMeEnabled", "true");
		// Use a non-secure cookie in tests since the mock request is not over HTTPS
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.rememberMeCookieSecure", "false");
		AuthenticationConfig.setProperty("authentication.scheme.primary.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.loginPage", "/primaryLogin");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.usernameParam", "uname");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.passwordParam", "pw");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users", "admin,tester,other");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.admin.password", "adminPassword");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.tester.password", "primaryPw");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.tester.secondaryType", "secondary");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.other.password", "otherPw");
		AuthenticationConfig.setProperty("authentication.scheme.primary.config.users.other.secondaryType", "secondary");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.loginPage", "/secondaryLogin");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.usernameParam", "uname2");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.passwordParam", "pw2");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.users", "tester,other");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.users.tester.password", "secondaryPw");
		AuthenticationConfig.setProperty("authentication.scheme.secondary.config.users.other.password", "otherSecondary");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		session = newSession();
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme.getClass(), equalTo(MockTwoFactorAuthenticationScheme.class));
		authenticationScheme = (MockTwoFactorAuthenticationScheme) scheme;
		newAuthenticationSession();
		UserLoginTracker.setLoginOnThread(userLogin);
	}

	@AfterEach
	@Override
	public void teardown() {
		UserLoginTracker.removeLoginFromThread();
		super.teardown();
	}

	private void newAuthenticationSession() {
		request = newPostRequest("192.168.1.1", "/login");
		request.setSession(session);
		response = newResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		userLogin = authenticationSession.getUserLogin();
	}

	private AuthenticationCredentials submit(String userParam, String userValue, String passParam, String passValue,
	                                         String rememberMe, Cookie... cookies) {
		newAuthenticationSession();
		if (userValue != null) {
			request.setParameter(userParam, userValue);
		}
		if (passValue != null) {
			request.setParameter(passParam, passValue);
		}
		if (rememberMe != null) {
			request.setParameter("rememberMe", rememberMe);
		}
		if (cookies != null && cookies.length > 0) {
			request.setCookies(cookies);
		}
		return authenticationScheme.getCredentials(authenticationSession);
	}

	private AuthenticationCredentials primary(String username, String password, String rememberMe, Cookie... cookies) {
		return submit("uname", username, "pw", password, rememberMe, cookies);
	}

	private AuthenticationCredentials secondary(String username, String password, String rememberMe) {
		return submit("uname2", username, "pw2", password, rememberMe);
	}

	private Cookie issuedCookie() {
		// Avoid response.getCookie() because Spring's helper invokes Cookie.isHttpOnly(), which is missing on the
		// legacy servlet-api 2.3 jar that velocity-tools pulls in for tests.
		Cookie[] cookies = response.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (COOKIE_NAME.equals(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}

	private void newHttpSession() {
		session = newSession();
		newAuthenticationSession();
		UserLoginTracker.setLoginOnThread(userLogin);
	}

	@Test
	public void shouldIssueCookieWhenRememberMeRequested() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials credentials = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, credentials);

		Cookie issued = issuedCookie();
		assertThat(issued, notNullValue());
		assertThat(issued.getValue(), notNullValue());
		assertThat(issued.getPath(), equalTo("/"));
		assertThat(issued.getSecure(), equalTo(false));
		assertThat(issued.getMaxAge(), equalTo(30 * 86_400));
		User user = userLogin.getUser();
		assertThat(user.getUserProperties().keySet().stream()
				.anyMatch(k -> k.startsWith("authentication.2fa.rememberMe.")), equalTo(true));
	}

	@Test
	public void shouldNotIssueCookieWhenRememberMeNotRequested() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials credentials = secondary("tester", "secondaryPw", null);
		authenticationSession.authenticate(authenticationScheme, credentials);

		assertThat(issuedCookie(), nullValue());
		User user = userLogin.getUser();
		assertThat(user.getUserProperties().keySet().stream()
				.anyMatch(k -> k.startsWith("authentication.2fa.rememberMe.")), equalTo(false));
	}

	@Test
	public void shouldNotIssueCookieWhenRememberMeDisabled() {
		AuthenticationConfig.setProperty("authentication.scheme.2fa.config.rememberMeEnabled", "false");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		authenticationScheme = (MockTwoFactorAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme();

		primary("tester", "primaryPw", null);
		AuthenticationCredentials credentials = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, credentials);

		assertThat(issuedCookie(), nullValue());
	}

	@Test
	public void shouldNotIssueCookieWhenUserHasNoSecondaryConfigured() {
		AuthenticationCredentials credentials = primary("admin", "adminPassword", "true");
		authenticationSession.authenticate(authenticationScheme, credentials);
		assertThat(issuedCookie(), nullValue());
	}

	@Test
	public void shouldBypassSecondaryWithValidCookie() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials credentials = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, credentials);
		Cookie cookie = issuedCookie();
		assertThat(cookie, notNullValue());

		newHttpSession();
		AuthenticationCredentials creds = primary("tester", "primaryPw", null, cookie);
		assertThat(creds, notNullValue());
		assertThat(userLogin.isCredentialValidated("primary"), equalTo(true));
		assertThat(userLogin.isCredentialValidated("secondary"), equalTo(true));
		assertThat(userLogin.getUser().getUsername(), equalTo("tester"));
	}

	@Test
	public void shouldRotateCookieAfterBypass() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds1 = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds1);
		Cookie cookieA = issuedCookie();
		String seriesA = cookieA.getValue().split("\\.")[0];

		newHttpSession();
		AuthenticationCredentials creds2 = primary("tester", "primaryPw", null, cookieA);
		authenticationSession.authenticate(authenticationScheme, creds2);
		Cookie cookieB = issuedCookie();
		assertThat(cookieB, notNullValue());
		String seriesB = cookieB.getValue().split("\\.")[0];
		assertThat(seriesA.equals(seriesB), equalTo(false));

		User user = userLogin.getUser();
		assertThat(user.getUserProperties().containsKey("authentication.2fa.rememberMe." + seriesA), equalTo(false));
		assertThat(user.getUserProperties().containsKey("authentication.2fa.rememberMe." + seriesB), equalTo(true));
	}

	@Test
	public void shouldRejectExpiredCookie() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds);
		Cookie cookie = issuedCookie();
		String series = cookie.getValue().split("\\.")[0];

		User user = userLogin.getUser();
		String storedKey = "authentication.2fa.rememberMe." + series;
		String stored = user.getUserProperty(storedKey);
		String hash = stored.substring(0, stored.lastIndexOf(':'));
		user.setUserProperty(storedKey, hash + ":" + (System.currentTimeMillis() - 1000));

		newHttpSession();
		primary("tester", "primaryPw", null, cookie);
		assertThat(userLogin.isCredentialValidated("secondary"), equalTo(false));
		assertThat(user.getUserProperties().containsKey(storedKey), equalTo(false));
	}

	@Test
	public void shouldRejectTamperedCookie() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds);
		Cookie cookie = issuedCookie();
		String[] parts = cookie.getValue().split("\\.");
		Cookie tampered = new Cookie(COOKIE_NAME, parts[0] + ".not-the-right-token");

		User user = userLogin.getUser();
		String storedKey = "authentication.2fa.rememberMe." + parts[0];
		assertThat(user.getUserProperty(storedKey), notNullValue());

		newHttpSession();
		primary("tester", "primaryPw", null, tampered);
		assertThat(userLogin.isCredentialValidated("secondary"), equalTo(false));
		assertThat(user.getUserProperties().containsKey(storedKey), equalTo(false));
	}

	@Test
	public void shouldRejectCookieFromDifferentUser() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds);
		Cookie testersCookie = issuedCookie();

		newHttpSession();
		primary("other", "otherPw", null, testersCookie);
		assertThat(userLogin.isCredentialValidated("secondary"), equalTo(false));
	}

	@Test
	public void shouldSupportMultipleConcurrentSeries() {
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds1 = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds1);
		Cookie cookieBrowser1 = issuedCookie();

		newHttpSession();
		primary("tester", "primaryPw", null);
		AuthenticationCredentials creds2 = secondary("tester", "secondaryPw", "true");
		authenticationSession.authenticate(authenticationScheme, creds2);
		Cookie cookieBrowser2 = issuedCookie();

		assertThat(cookieBrowser1.getValue().equals(cookieBrowser2.getValue()), equalTo(false));

		User user = userLogin.getUser();
		long count = user.getUserProperties().keySet().stream()
				.filter(k -> k.startsWith("authentication.2fa.rememberMe.")).count();
		assertThat(count, equalTo(2L));
	}
}
