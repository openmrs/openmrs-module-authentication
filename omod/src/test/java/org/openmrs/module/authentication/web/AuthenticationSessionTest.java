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

	public void testSetupOfSessionAttributes(AuthenticationContext context) {
		assertThat(context.getContextId(), notNullValue());
		assertThat(context.getHttpSessionId(), notNullValue());
		assertThat(context.getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldSetupWithSessionConstructor() {
		MockHttpSession session = newSession("testing");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		testSetupOfSessionAttributes(authenticationSession.getAuthenticationContext());
	}

	@Test
	public void shouldSetupWithRequestConstructor() {
		MockHttpServletRequest request = newGetRequest("/", "192.168.1.1");
		request.setSession(newSession("testing"));
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		testSetupOfSessionAttributes(authenticationSession.getAuthenticationContext());
		assertThat(authenticationSession.getAuthenticationContext().getIpAddress(), equalTo("192.168.1.1"));
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
		AuthenticationContext ctx = new AuthenticationContext();
		setAuthenticationContext(session, ctx);
		AuthenticationContext context1 = new AuthenticationSession(session).getAuthenticationContext();
		AuthenticationContext context2 = new AuthenticationSession(session).getAuthenticationContext();
		assertThat(context1, equalTo(ctx));
		assertThat(context2, equalTo(ctx));
	}

	@Test
	public void shouldGetIpAddressFromSessionIfExists() {
		MockHttpSession session = newSession("testing");
		AuthenticationContext ctx = new AuthenticationContext();
		ctx.setIpAddress("session-ip");
		setAuthenticationContext(session, ctx);
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationContext().getIpAddress(), equalTo("session-ip"));
	}

	@Test
	public void shouldGetIpAddressFromRequestIfExistsAndNotOnSession() {
		MockHttpSession session = newSession("testing");
		AuthenticationContext ctx = new AuthenticationContext();
		setAuthenticationContext(session, ctx);
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		assertThat(authenticationSession.getAuthenticationContext().getIpAddress(), equalTo("request-ip"));
	}

	@Test
	public void shouldUpdateIpAddressInSessionAndLogWarningIfRequestIpDiffers() {
		Logger sessionLogger = (Logger) LogManager.getLogger(AuthenticationSession.class);
		sessionLogger.setAdditive(false);
		sessionLogger.setLevel(Level.INFO);
		sessionLogger.addAppender(memoryAppender);
		MockHttpSession session = newSession("testing");
		AuthenticationContext ctx = new AuthenticationContext();
		ctx.setIpAddress("session-ip");
		setAuthenticationContext(session, ctx);
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		assertThat(authenticationSession.getAuthenticationContext().getIpAddress(), equalTo("request-ip"));
		assertLastLogContains("IP Address change detected: 'session-ip' -> 'request-ip'");
	}

	@Test
	public void shouldGetUsernameFromSession() {
		MockHttpSession session = newSession("testing");
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		assertThat(authenticationSession.getAuthenticationContext().getUsername(), equalTo("testing"));
	}

	@Test
	public void shouldGetAllAttributesFromSession() {
		MockHttpSession session = newSession("testing");
		MockHttpServletRequest request = newGetRequest("/", "request-ip");
		request.setSession(session);
		AuthenticationSession authenticationSession = new AuthenticationSession(request, newResponse());
		AuthenticationContext context = authenticationSession.getAuthenticationContext();
		Map<String, Object> attributes = authenticationSession.getHttpSessionAttributes();
		assertThat(attributes.size(), equalTo(1));
		assertThat(attributes.get(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY), equalTo(context));
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
		AuthenticationContext context = session.getAuthenticationContext();
		String contextId = context.getContextId();
		String httpSessionId = context.getHttpSessionId();
		session.regenerateHttpSession();
		AuthenticationContext context2 = session.getAuthenticationContext();
		assertThat(context2, equalTo(context));
		assertThat(context2.getContextId(), equalTo(contextId));
		assertThat(context2.getHttpSessionId(), not(httpSessionId));
	}
}