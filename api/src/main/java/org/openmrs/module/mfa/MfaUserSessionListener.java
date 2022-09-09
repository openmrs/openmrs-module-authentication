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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.UserSessionListener;
import org.openmrs.api.context.Context;
import org.springframework.stereotype.Component;

/**
 * This class contains the logic that is run every time this module is either started or shutdown
 */
@Component
public class MfaUserSessionListener implements UserSessionListener {
	
	private final Log log = LogFactory.getLog(getClass());

	@Override
	public void loggedInOrOut(User user, Event event, Status status) {
		log.debug("Context.isSessionOpen(): " + Context.isSessionOpen());
		log.debug("Context.isAuthenticated(): " + Context.isAuthenticated());
		log.debug("Context.getAuthenticatedUser(): " + Context.getAuthenticatedUser());
		log.info(event.name() + " " + status.name() + ": " + user.getUsername());
	}
}
