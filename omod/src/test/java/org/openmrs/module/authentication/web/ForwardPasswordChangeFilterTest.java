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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockForcePasswordChangeFilter;
import org.openmrs.util.OpenmrsConstants;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class ForwardPasswordChangeFilterTest extends BaseWebAuthenticationTest {

	MockForcePasswordChangeFilter filter;
	MockFilterChain chain;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	User user;

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		session = new MockHttpSession();
		request = new MockHttpServletRequest();
		request.setRemoteAddr("192.168.1.1");
		request.setContextPath("/");
		request.setSession(session);
		response = new MockHttpServletResponse();
		filter = new MockForcePasswordChangeFilter(newFilterConfig("forcePasswordChangeFilter"));
		chain = new MockFilterChain();
		user = new User();
		user.setUserId(1);
		user.setUsername("admin");
	}

	@Test
	public void shouldForcePasswordChangeForAuthenticatedUserIfConfiguredAndRequired() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "true");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "/passwordChange.htm");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		filter.setAuthenticatedUser(user);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/passwordChange.htm"));
	}

	@Test
	public void shouldNotForcePasswordChangeForAuthenticatedUserIfConfiguredAndNotRequired() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "true");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "/passwordChange.htm");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		filter.setAuthenticatedUser(user);
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldNotForcePasswordChangeForNonAuthenticatedUser() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "true");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "/passwordChange.htm");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldNotForcePasswordChangeByDefaultForAuthenticatedUser() throws Exception {
		filter.init(null);
		filter.setAuthenticatedUser(user);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldNotForcePasswordChangeForAuthenticatedUserIfChangePasswordUrlIsNull() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "true");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		filter.setAuthenticatedUser(user);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldNotForcePasswordChangeForAuthenticatedUserIfExplicitlyDisabled() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "false");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "/passwordChange.htm");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		filter.setAuthenticatedUser(user);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldForcePasswordChangeForAuthenticatedUserIfUrlIsWhitelisted() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, "true");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_URL, "/passwordChange.htm");
		AuthenticationConfig.setProperty(AuthenticationConfig.PASSWORD_CHANGE_WHITE_LIST, "/patientDashboard.htm");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		filter.init(null);
		filter.setAuthenticatedUser(user);
		user.setUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD, "true");
		request.setMethod("GET");
		request.setRequestURI("/patientDashboard.htm");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@AfterEach
	@Override
	public void teardown() {
		super.teardown();
		filter.destroy();
		UserLoginTracker.removeLoginFromThread();
	}
}