/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.openmrs.User;
import org.openmrs.UserSessionListener;
import org.springframework.stereotype.Component;

import java.util.Date;

import static org.openmrs.module.authentication.AuthenticationEvent.LOGIN_FAILED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGIN_SUCCEEDED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGOUT_FAILED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGOUT_SUCCEEDED;

/**
 * Implementation of UserSessionListener which logs message with a marker every time a user is logged in or out
 */
@Component
public class AuthenticationUserSessionListener implements UserSessionListener {

	@Override
	public void loggedInOrOut(User user, Event event, Status status) {
		AuthenticationContext context = AuthenticationEventLog.getContextForThread();
		if (context != null && (context.getUser() == null || !context.getUser().equals(user))) {
			throw new IllegalStateException("AuthenticationContext user does not match the event user");
		}
		AuthenticationEvent authenticationEvent = null;
		if (event == Event.LOGIN) {
			if (status == Status.SUCCESS) {
				authenticationEvent = LOGIN_SUCCEEDED;
				if (context != null && context.getLoginDate() == null) {
					context.setLoginDate(new Date());
				}
			}
			else if (status == Status.FAIL) {
				authenticationEvent = LOGIN_FAILED;
			}
		}
		else if (event == Event.LOGOUT) {
			if (status == Status.SUCCESS) {
				if (context != null && context.getLogoutDate() == null) {
					context.setLogoutDate(new Date());
				}
				authenticationEvent = LOGOUT_SUCCEEDED;
			}
			else if (status == Status.FAIL) {
				authenticationEvent = LOGOUT_FAILED;
			}
		}
		AuthenticationEventLog.logEvent(authenticationEvent);
	}
}
