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

import org.openmrs.module.authentication.web.AuthenticationFilter;
import org.openmrs.module.authentication.web.AuthenticationSession;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;

/**
 * Mock Authentication Filter, primarily used to mock the authentication session
 */
public class MockAuthenticationFilter extends AuthenticationFilter {

	private AuthenticationSession authenticationSession;

	public MockAuthenticationFilter(FilterConfig filterConfig) {
		super();
		init(filterConfig);
	}

	@Override
	protected AuthenticationSession getAuthenticationSession(HttpServletRequest request) {
		return authenticationSession;
	}

	public void setAuthenticationSession(AuthenticationSession authenticationSession) {
		this.authenticationSession = authenticationSession;
	}
}