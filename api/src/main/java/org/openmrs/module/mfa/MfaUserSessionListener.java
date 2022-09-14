/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.openmrs.User;
import org.openmrs.UserSessionListener;
import org.springframework.stereotype.Component;

/**
 * This class contains the logic that is run every time this module is either started or shutdown
 */
@Component
public class MfaUserSessionListener implements UserSessionListener {

	@Override
	public void loggedInOrOut(User user, Event event, Status status) {
		MfaLogger.Event e = null;
		if (event == Event.LOGIN) {
			if (status == Status.SUCCESS) {
				e = MfaLogger.Event.LOGIN_SUCCEEDED;
			}
			else if (status == Status.FAIL) {
				e = MfaLogger.Event.LOGIN_FAILED;
			}
		}
		else if (event == Event.LOGOUT) {
			if (status == Status.SUCCESS) {
				e = MfaLogger.Event.LOGOUT_SUCCEEDED;
			}
			else if (status == Status.FAIL) {
				e = MfaLogger.Event.LOGOUT_FAILED;
			}
		}
		MfaLogger.logEvent(e);
	}
}
