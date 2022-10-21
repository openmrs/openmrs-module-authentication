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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.module.authentication.AuthenticationEventLog;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.http.HttpSessionEvent;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationHttpSessionListenerTest extends BaseWebAuthenticationTest {

	AuthenticationHttpSessionListener listener = new AuthenticationHttpSessionListener();
	Logger logger = (Logger) LogManager.getLogger(AuthenticationHttpSessionListener.class);

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		logger.setAdditive(false);
		logger.setLevel(Level.DEBUG);
		logger.addAppender(memoryAppender);
	}

	@AfterEach
	@Override
	public void teardown() {
		logger.removeAppender(memoryAppender);
		super.teardown();
	}

	@Test
	public void shouldLogSessionCreationEvent() {
		MockHttpSession session = newSession();
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		AuthenticationEventLog.contextInitialized(authenticationSession.getAuthenticationContext());
		listener.sessionCreated(new HttpSessionEvent(session));
		assertLastLogContains("Http Session Created: " + authenticationSession);
	}
	@Test
	public void shouldCreateNewAuthenticationSession() {
		MockHttpSession session = newSession();
		assertThat(getAuthenticationContext(session), nullValue());
		listener.sessionCreated(new HttpSessionEvent(session));
		assertThat(getAuthenticationContext(session), notNullValue());
	}

	@Test
	public void shouldLogSessionDestroyedEvent() {
		MockHttpSession session = newSession();
		AuthenticationSession authenticationSession = new AuthenticationSession(session);
		listener.sessionDestroyed(new HttpSessionEvent(session));
		assertLastLogContains("Http Session Destroyed: " + authenticationSession);
	}
}