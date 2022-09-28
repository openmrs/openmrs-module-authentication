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
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;
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

	public void testSetupOfSessionAttributes(AuthenticationSession authenticationSession) {
		assertThat(authenticationSession.getAuthenticationSessionId(), notNullValue());
		assertThat(authenticationSession.getHttpSessionId(), notNullValue());
		assertThat(authenticationSession.getUsername(), equalTo("testing"));
		assertThat(authenticationSession.getUserId(), equalTo("12345"));
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.HTTP_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), notNullValue());
	}

	@Test
	public void shouldSetupWithSessionConstructor() {
		MockHttpSession session = newSession("testing", "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		testSetupOfSessionAttributes(authenticationSession);
	}

	@Test
	public void shouldSetupWithRequestConstructor() {
		MockHttpServletRequest request = newGetRequest("/", "192.168.1.1");
		request.setSession(newSession("testing", "12345"));
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		testSetupOfSessionAttributes(authenticationSession);
		assertThat(authenticationSession.getIpAddress(), equalTo("192.168.1.1"));
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS), equalTo("192.168.1.1"));
	}

	@Test
	public void shouldGetNewAuthenticationContext() {
		MockHttpSession session = newSession();
		assertThat(getAuthenticationContext(session), nullValue());
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		assertThat(context, notNullValue());
		assertThat(getAuthenticationContext(session), notNullValue());
	}

	@Test
	public void shouldGetExistingAuthenticationContext() {
		MockHttpSession session = newSession();
		assertThat(getAuthenticationContext(session), nullValue());
		AuthenticationContext context1 = new AuthenticationSession(session).getAuthenticationContext();
		AuthenticationContext context2 = new AuthenticationSession(session).getAuthenticationContext();
		assertThat(context1, equalTo(context2));
	}

	@Test
	public void shouldGetNewAuthenticationSessionId() {
		MockHttpSession session = newSession();
		assertThat(getAuthenticationSessionId(session), nullValue());
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationSessionId(), notNullValue());
		assertThat(getAuthenticationSessionId(session), equalTo(authenticationSession.getAuthenticationSessionId()));
	}

	@Test
	public void shouldGetAuthenticationSessionIdFromSessionIfExists() {
		MockHttpSession session = newSession();
		session.setAttribute(AuthenticationSession.AUTHENTICATION_SESSION_ID_KEY, "abcde");
		AuthenticationLogger.addToContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID, "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationSessionId(), equalTo("abcde"));
	}

	@Test
	public void shouldGetAuthenticationSessionIdFromThreadIfExistsAndNotOnSession() {
		MockHttpSession session = newSession();
		AuthenticationLogger.addToContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID, "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationSessionId(), equalTo("12345"));
	}

	@Test
	public void shouldGetIpAddressFromSessionIfExists() {
		MockHttpSession session = newSession("testing", "12345");
		session.setAttribute(AuthenticationSession.AUTHENTICATION_IP_ADDRESS, "session-ip");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getIpAddress(), equalTo("session-ip"));
	}

	@Test
	public void shouldGetIpAddressFromRequestIfExistsAndNotOnSession() {
		MockHttpSession session = newSession("testing", "12345");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		assertThat(authenticationSession.getIpAddress(), equalTo("request-ip"));
	}

	@Test
	public void shouldUpdateIpAddressInSessionAndLogWarningIfRequestIpDiffers() {
		Logger sessionLogger = (Logger) LogManager.getLogger(AuthenticationSession.class);
		sessionLogger.setAdditive(false);
		sessionLogger.setLevel(Level.INFO);
		sessionLogger.addAppender(memoryAppender);
		MockHttpSession session = newSession("testing", "12345");
		session.setAttribute(AuthenticationSession.AUTHENTICATION_IP_ADDRESS, "session-ip");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		assertThat(authenticationSession.getIpAddress(), equalTo("request-ip"));
		assertLastLogContains("IP Address change detected from 'session-ip' to 'request-ip'");
	}

	@Test
	public void shouldGetIpAddressFromThreadIfExistsAndNotOnSessionOrRequest() {
		MockHttpSession session = newSession("testing", "12345");
		AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, "thread-ip");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getIpAddress(), equalTo("thread-ip"));
	}

	@Test
	public void shouldGetUsernameFromSession() {
		MockHttpSession session = newSession("testing", "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldSetUsernameOnSessionAndThread() {
		MockHttpSession session = newSession();
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUsername(), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), nullValue());
		authenticationSession.setUsername("testing");
		assertThat(authenticationSession.getUsername(), equalTo("testing"));
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), equalTo("testing"));
	}

	@Test
	public void shouldGetUserIdFromSession() {
		MockHttpSession session = newSession("testing", "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUserId(), equalTo("12345"));
	}

	@Test
	public void shouldSetUserIdOnSessionAndThread() {
		MockHttpSession session = newSession();
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getUserId(), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), nullValue());
		authenticationSession.setUserId("12345");
		assertThat(authenticationSession.getUserId(), equalTo("12345"));
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), equalTo("12345"));
	}

	@Test
	public void shouldGetHttpSessionIdFromSession() {
		MockHttpSession session = newSession("testing", "12345");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getHttpSessionId(), equalTo(session.getId()));
	}

	@Test
	public void shouldGetAllAttributesFromSession() {
		MockHttpSession session = newSession("testing", "12345");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		Map<String, Object> attributes = authenticationSession.getHttpSessionAttributes();
		assertThat(attributes.size(), equalTo(5));
	}

	@Test
	public void shouldGetParameterFromRequest() {
		MockHttpSession session = newSession();
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setParameter("username", "admin");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		assertThat(authenticationSession.getRequestParam("username"), equalTo("admin"));
	}

	@Test
	public void shouldRemoveAuthenticationContext() {
		MockHttpSession session = newSession();
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY), notNullValue());
		authenticationSession.removeAuthenticationContext();
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY), nullValue());
		assertThat(authenticationSession.getAuthenticationContext(), not(context));
	}

	@Test
	public void shouldDestroyAuthenticationSession() {
		MockHttpSession session = newSession("testing", "12345");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY), notNullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_SESSION_ID_KEY), notNullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_IP_ADDRESS), notNullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_USERNAME), notNullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_USER_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.HTTP_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS), notNullValue());
		authenticationSession.destroy();
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY), nullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_SESSION_ID_KEY), nullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_IP_ADDRESS), nullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_USERNAME), nullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_USER_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.HTTP_SESSION_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS), nullValue());
	}

	@Test
	public void shouldReturnFalseForUserAuthenticatedIfNoSessionIsOpen() {
		AuthenticationSession session = new AuthenticationSession(newSession("admin", "test"));
		assertThat(session.isUserAuthenticated(), is(false));
	}
}