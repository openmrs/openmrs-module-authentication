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

import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * Called each time a http session is created or destroyed
 */
@Component
public class AuthenticationHttpSessionListener implements HttpSessionListener {

	@Override
	public void sessionCreated(HttpSessionEvent httpSessionEvent) {
		HttpSession session = httpSessionEvent.getSession();
		addUserToLoggerContext();
		AuthenticationLogger.addToContext(AuthenticationLogger.SESSION_ID, session.getId());
		AuthenticationLogger.logEvent(AuthenticationLogger.Event.AUTHENTICATION_SESSION_CREATED, session.getId());
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
		HttpSession session = httpSessionEvent.getSession();
		addUserToLoggerContext();
		AuthenticationLogger.logEvent(AuthenticationLogger.Event.AUTHENTICATION_SESSION_DESTROYED, session.getId());
		AuthenticationLogger.clearContext();
	}

	private void addUserToLoggerContext() {
		if (Context.isSessionOpen()) {
			AuthenticationLogger.addUserToContext(Context.getAuthenticatedUser());
		}
	}
}
