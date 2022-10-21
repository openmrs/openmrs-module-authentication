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
import org.openmrs.api.context.Authenticated;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.web.AuthenticationSession;
import org.openmrs.module.authentication.web.WebAuthenticationScheme;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Mock Authentication Session, primarily useful to mock information about the authenticated user
 */
public class MockAuthenticationSession extends AuthenticationSession {

	private User authenticatedUser;

	public MockAuthenticationSession(HttpServletRequest request, HttpServletResponse response) {
		super(request, response);
	}

	@Override
	public boolean isUserAuthenticated() {
		return authenticatedUser != null;
	}

	@Override
	public Authenticated authenticate(WebAuthenticationScheme scheme, AuthenticationCredentials credentials) {
		String startingScheme = AuthenticationConfig.getProperty(AuthenticationConfig.SCHEME);
		try {
			AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME, "xxx");
			return super.authenticate(scheme, credentials);
		}
		finally {
			AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME, startingScheme);
		}
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