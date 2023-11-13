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

/**
 * Implementation of UserSessionListener which creates or updates a UserLogin instance
 */
@Component
public class AuthenticationUserSessionListener implements UserSessionListener {

	@Override
	public void loggedInOrOut(User user, Event event, Status status) {
		UserLogin login = UserLoginTracker.getLoginOnThread();
		boolean addedToThread = false;
		try {
			if (login == null) {
				login = new UserLogin();
				UserLoginTracker.setLoginOnThread(login);
				addedToThread = true;
			}
			login.setLastActivityDate(new Date());
			if (login.getUser() == null) {
				login.setUser(user);
			}
			if (event == Event.LOGIN) {
				if (status == Status.SUCCESS) {
					login.loginSuccessful();
				} else if (status == Status.FAIL) {
					login.loginFailed();
				}
			} else if (event == Event.LOGOUT) {
				if (status == Status.SUCCESS) {
					login.logoutSucceeded();
				} else if (status == Status.FAIL) {
					login.logoutFailed();
				}
			}
		}
		finally {
			if (addedToThread) {
				UserLoginTracker.removeLoginFromThread();
			}
		}
	}
}
