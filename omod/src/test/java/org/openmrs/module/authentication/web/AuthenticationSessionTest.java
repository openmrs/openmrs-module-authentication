/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.junit.jupiter.api.Test;
import org.openmrs.module.authentication.UserLogin;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationSessionTest extends BaseWebAuthenticationTest {

	public void testSetupOfSessionAttributes(UserLogin userLogin) {
		assertThat(userLogin.getLoginId(), notNullValue());
		assertThat(userLogin.getHttpSessionId(), notNullValue());
		assertThat(userLogin.getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldSetupWithSessionConstructor() {
		MockHttpSession session = newSession("testing");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		testSetupOfSessionAttributes(authenticationSession.getUserLogin());
	}

	@Test
	public void shouldSetupWithRequestConstructor() {
		MockHttpServletRequest request = newGetRequest("/", "192.168.1.1");
		request.setSession(newSession("testing"));
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		testSetupOfSessionAttributes(authenticationSession.getUserLogin());
		assertThat(authenticationSession.getUserLogin().getIpAddress(), equalTo("192.168.1.1"));
	}

	@Test
	public void shouldGetNewUserLogin() {
		MockHttpSession session = newSession();
		assertThat(getUserLogin(session), nullValue());
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		UserLogin userLogin = authenticationSession.getUserLogin();
		assertThat(userLogin, notNullValue());
		assertThat(getUserLogin(session), notNullValue());
	}

	@Test
	public void shouldGetExistingUserLogin() {
		MockHttpSession session = newSession();
		assertThat(getUserLogin(session), nullValue());
		UserLogin ctx = new UserLogin();
		setUserLogin(session, ctx);
		UserLogin userLogin1 = new AuthenticationSession(session).getUserLogin();
		UserLogin userLogin2 = new AuthenticationSession(session).getUserLogin();
		assertThat(userLogin1, equalTo(ctx));
		assertThat(userLogin2, equalTo(ctx));
	}

	@Test
	public void shouldGetIpAddressFromSessionIfExists() {
		MockHttpSession session = newSession("testing");
		UserLogin ctx = new UserLogin();
		ctx.setIpAddress("session-ip");
		setUserLogin(session, ctx);
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUserLogin().getIpAddress(), equalTo("session-ip"));
	}

	@Test
	public void shouldGetIpAddressFromRequestIfExistsAndNotOnSession() {
		MockHttpSession session = newSession("testing");
		UserLogin ctx = new UserLogin();
		setUserLogin(session, ctx);
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		assertThat(authenticationSession.getUserLogin().getIpAddress(), equalTo("request-ip"));
	}

	@Test
	public void shouldUpdateIpAddressInSessionAndLogWarningIfRequestIpDiffers() {
		Logger sessionLogger = (Logger) LogManager.getLogger(AuthenticationSession.class);
		sessionLogger.setAdditive(false);
		sessionLogger.setLevel(Level.INFO);
		sessionLogger.addAppender(memoryAppender);
		MockHttpSession session = newSession("testing");
		UserLogin userLogin = new UserLogin();
		userLogin.setIpAddress("session-ip");
		setUserLogin(session, userLogin);
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		assertThat(authenticationSession.getUserLogin().getIpAddress(), equalTo("request-ip"));
		assertLastLogContains("IP Address change detected: 'session-ip' -> 'request-ip'");
	}

	@Test
	public void shouldGetUsernameFromSession() {
		MockHttpSession session = newSession("testing");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUserLogin().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldGetAllAttributesFromSession() {
		MockHttpSession session = newSession("testing");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		UserLogin userLogin = authenticationSession.getUserLogin();
		Map<String, Object> attributes = authenticationSession.getHttpSessionAttributes();
		assertThat(attributes.size(), equalTo(1));
		assertThat(attributes.get(AuthenticationSession.AUTHENTICATION_USER_LOGIN), equalTo(userLogin));
	}

	@Test
	public void shouldGetParameterFromRequest() {
		MockHttpSession session = newSession();
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setParameter("username", "admin");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		assertThat(authenticationSession.getRequestParam("username"), equalTo("admin"));
	}

	@Test
	public void shouldReturnFalseForUserAuthenticatedIfNoSessionIsOpen() {
		AuthenticationSession session = new AuthenticationSession(newSession("admin"));
		assertThat(session.isUserAuthenticated(), is(false));
	}

	@Test
	public void shouldRegenerateSession() {
		AuthenticationSession session = new AuthenticationSession(new MockHttpServletRequest(), newResponse());
		UserLogin userLogin = session.getUserLogin();
		String loginId = userLogin.getLoginId();
		String httpSessionId = userLogin.getHttpSessionId();
		session.regenerateHttpSession();
		UserLogin login2 = session.getUserLogin();
		assertThat(login2, equalTo(userLogin));
		assertThat(login2.getLoginId(), equalTo(loginId));
		assertThat(login2.getHttpSessionId(), not(httpSessionId));
	}
}