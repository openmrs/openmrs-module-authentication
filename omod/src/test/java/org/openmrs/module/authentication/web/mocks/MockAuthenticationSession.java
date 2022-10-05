/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.mocks;

import org.openmrs.User;
import org.openmrs.module.authentication.web.AuthenticationSession;

import javax.servlet.http.HttpServletRequest;

/**
 * Mock Authentication Session, primarily useful to mock information about the authenticated user
 */
public class MockAuthenticationSession extends AuthenticationSession {

	private User authenticatedUser;

	public MockAuthenticationSession(HttpServletRequest request) {
		super(request);
	}

	@Override
	public boolean isUserAuthenticated() {
		return authenticatedUser != null;
	}

	public User getAuthenticatedUser() {
		return authenticatedUser;
	}

	public void setAuthenticatedUser(User authenticatedUser) {
		this.authenticatedUser = authenticatedUser;
	}

	@Override
	public void refreshDefaultLocale() {
	}
}