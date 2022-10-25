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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * Called each time a http session is created or destroyed
 */
@Component
public class AuthenticationHttpSessionListener implements HttpSessionListener {

	private static final Logger log = LogManager.getLogger(AuthenticationHttpSessionListener.class);

	/**
	 * This ensures a new AuthenticationSession is created and initialized with appropriate values
	 * @see AuthenticationSession which will initialize with existing values if an authenticated user is found
	 * @param httpSessionEvent the event passed at session creation
	 */
	@Override
	public void sessionCreated(HttpSessionEvent httpSessionEvent) {
		// Instantiating the AuthenticationSession here ensures that the UserLogin is created here
		AuthenticationSession session = new AuthenticationSession(httpSessionEvent.getSession());
		log.debug("Http Session Created: " + session);
		UserLogin login = session.getUserLogin();
		UserLoginTracker.setLoginOnThread(login);
		if (session.isUserAuthenticated()) {
			UserLoginTracker.addActiveLogin(login);
		}
	}

	/**
	 * If this event coincides with a logged-out user, then ensure the authentication session is destroyed
	 * @param httpSessionEvent the event passed at session creation
	 */
	@Override
	public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
		AuthenticationSession session = new AuthenticationSession(httpSessionEvent.getSession());
		log.debug("Http Session Destroyed: " + session);
		UserLogin login = session.getUserLogin();
		if (!session.isSessionRegenerating() && login.getLoginDate() != null && login.getLogoutDate() == null) {
			login.loginExpired();
		}
		UserLoginTracker.removeLoginFromThread();
		UserLoginTracker.removeActiveLogin(login);
	}
}