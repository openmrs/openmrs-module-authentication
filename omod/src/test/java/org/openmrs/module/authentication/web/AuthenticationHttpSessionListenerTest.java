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

import org.junit.jupiter.api.Test;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationHttpSessionListenerTest extends BaseWebAuthenticationTest {

	AuthenticationHttpSessionListener listener = new AuthenticationHttpSessionListener();

	@Test
	public void shouldLogSessionCreationEvent() {
		MockHttpSession session = newSession();
		listener.sessionCreated(new HttpSessionEvent(session));
		assertLastLogContains("marker=AUTHENTICATION_SESSION_CREATED");
		assertLastLogContains("message=httpSessionId=" + session.getId());
	}

	@Test
	public void shouldCreateNewAuthenticationSession() {
		MockHttpSession session = newSession();
		assertThat(getAuthenticationContext(session), nullValue());
		assertThat(getUsername(session), nullValue());
		assertThat(getAuthenticationSessionId(session), nullValue());
		listener.sessionCreated(new HttpSessionEvent(session));
		assertThat(getAuthenticationContext(session), nullValue());
		assertThat(getUsername(session), nullValue());
		String authenticationSessionId = getAuthenticationSessionId(session);
		assertThat(authenticationSessionId, notNullValue());
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationSessionId(), equalTo(authenticationSessionId));
	}

	@Test
	public void shouldNotCreateNewAuthenticationSessionWithinSameThread() {
		MockHttpSession session1 = newSession();
		assertThat(getAuthenticationSessionId(session1), nullValue());
		listener.sessionCreated(new HttpSessionEvent(session1));
		String authSessionId1 = getAuthenticationSessionId(session1);
		assertThat(authSessionId1, notNullValue());

		MockHttpSession session2 = newSession();
		assertThat(getAuthenticationSessionId(session2), nullValue());
		listener.sessionCreated(new HttpSessionEvent(session2));
		String authSessionId2 = getAuthenticationSessionId(session2);
		assertThat(authSessionId2, notNullValue());

		assertThat(session1, not(session2));
		assertThat(session1.getId(), not(session2.getId()));
		assertThat(authSessionId1, equalTo(authSessionId2));
	}

	@Test
	public void shouldLogSessionDestroyedEvent() {
		MockHttpSession session = newSession();
		listener.sessionDestroyed(new HttpSessionEvent(session));
		assertLastLogContains("marker=AUTHENTICATION_SESSION_DESTROYED");
		assertLastLogContains("message=httpSessionId="+ session.getId());
	}

	@Test
	public void shouldDestroySessionIfUserIsNotAuthenticated() {
		MockHttpServletRequest request = newGetRequest("/", "192.168.1.1");
		HttpSession session = request.getSession(true);
		session.setAttribute(AuthenticationSession.AUTHENTICATION_USERNAME, "testing");
		session.setAttribute(AuthenticationSession.AUTHENTICATION_USER_ID, "12345");

		AuthenticationSession authenticationSession = new AuthenticationSession(request);
		assertThat(authenticationSession.getAuthenticationSessionId(), notNullValue());
		assertThat(authenticationSession.getUsername(), equalTo("testing"));
		assertThat(authenticationSession.getUserId(), equalTo("12345"));
		assertThat(authenticationSession.getIpAddress(), equalTo("192.168.1.1"));
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.HTTP_SESSION_ID), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), notNullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), notNullValue());

		listener.sessionDestroyed(new HttpSessionEvent(session));

		assertThat(getAuthenticationSessionId(session), nullValue());
		assertThat(getUsername(session), nullValue());
		assertThat(getUserId(session), nullValue());
		assertThat(getIpAddress(session), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.HTTP_SESSION_ID), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USERNAME), nullValue());
		assertThat(AuthenticationLogger.getFromContext(AuthenticationLogger.USER_ID), nullValue());
	}
}