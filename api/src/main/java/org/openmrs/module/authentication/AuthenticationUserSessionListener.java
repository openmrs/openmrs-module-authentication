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

import org.apache.logging.log4j.Marker;
import org.openmrs.User;
import org.openmrs.UserSessionListener;
import org.springframework.stereotype.Component;

/**
 * Implementation of UserSessionListener which logs message with a marker every time a user is logged in or out
 */
@Component
public class AuthenticationUserSessionListener implements UserSessionListener {

	@Override
	public void loggedInOrOut(User user, Event event, Status status) {
		AuthenticationLogger.addUserToContext(user);
		Marker marker = null;
		if (event == Event.LOGIN) {
			if (status == Status.SUCCESS) {
				marker = AuthenticationLogger.LOGIN_SUCCEEDED;
			}
			else if (status == Status.FAIL) {
				marker = AuthenticationLogger.LOGIN_FAILED;
			}
		}
		else if (event == Event.LOGOUT) {
			if (status == Status.SUCCESS) {
				marker = AuthenticationLogger.LOGOUT_SUCCEEDED;
			}
			else if (status == Status.FAIL) {
				marker = AuthenticationLogger.LOGOUT_FAILED;
			}
		}
		AuthenticationLogger.logEvent(marker, "user=" + user.getUsername());
	}
}
