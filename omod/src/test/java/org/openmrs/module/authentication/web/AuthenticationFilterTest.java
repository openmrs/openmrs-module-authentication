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
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationContext;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationFilter;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.openmrs.module.authentication.web.scheme.WebAuthenticationScheme;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AuthenticationFilterTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockAuthenticationFilter filter;
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
		session.setAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY, new MockAuthenticationContext());
		request = new MockHttpServletRequest();
		request.setRemoteAddr("192.168.1.1");
		request.setContextPath("/openmrs");
		request.setSession(session);
		response = new MockHttpServletResponse();
		authenticationSession = new MockAuthenticationSession(request, response);
		filter = new MockAuthenticationFilter(newFilterConfig("authenticationFilter"));
		filter.setAuthenticationSession(authenticationSession);
		chain = new MockFilterChain();
		user = new User();
		user.setUserId(1);
		user.setUsername("admin");
	}

	public void setupTestThatInvokesAuthenticationCheck() {
		AuthenticationConfig.setProperty("authentication.scheme", "basic");
		AuthenticationConfig.setProperty("authentication.scheme.basic.type", MockBasicWebAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.loginPage", "/login.htm");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.users", "admin");
		AuthenticationConfig.setProperty("authentication.scheme.basic.config.users.admin.password", "adminPassword");
		setRuntimeProperties(AuthenticationConfig.getConfig());
		authenticationSession.setAuthenticatedUser(null);
		request.setMethod("GET");
		request.setRequestURI("/openmrs/patientDashboard.htm");
	}

	@Test
	public void shouldInvokeAuthenticationCheck() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
	}

	@Test
	public void shouldNotFilterIfUserIsAlreadyAuthenticated() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		authenticationSession.setAuthenticatedUser(user);
		assertThat(authenticationSession.isUserAuthenticated(), equalTo(true));
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
		assertThat(getAuthenticationContext(session), nullValue());
	}

	@Test
	public void shouldNotFilterIfAuthenticationSchemeIsNotWebAuthenticationScheme() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		Properties p = Context.getRuntimeProperties();
		p.remove("authentication.scheme");
		setRuntimeProperties(p);
		assertThat(authenticationSession.isUserAuthenticated(), equalTo(false));
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldNotFilterIfUrlIsWhitelisted() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		Properties p = Context.getRuntimeProperties();
		p.setProperty("authentication.whiteList", "/patientDashboard.htm,*.jpg");
		setRuntimeProperties(p);
		assertThat(authenticationSession.isUserAuthenticated(), equalTo(false));
		assertThat(Context.getAuthenticationScheme() instanceof WebAuthenticationScheme, equalTo(true));
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(false));
		assertThat(response.getRedirectedUrl(), equalTo(null));
	}

	@Test
	public void shouldClearLoggingContextAfterFilterExecutes() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(request, response, chain);
		assertThat(AuthenticationLogger.getContextValues().size(), equalTo(0));
	}

	@Test
	public void shouldRedirectToChallengeUrlForAuthenticationScheme() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
	}

	@Test
	public void shouldRedirectToSuccessUrlIfAuthenticationSucceeds() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/openmrs/patientDashboard.htm"));
	}

	@Test
	public void shouldRegenerateHttpSessionIfAuthenticationSucceeds() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		assertThat(session.isInvalid(), equalTo(false));
		AuthenticationSession session1 = new AuthenticationSession(request, newResponse());
		String authenticationSessionId = session1.getAuthenticationSessionId();
		String httpSessionId = session1.getHttpSessionId();
		int numAttributes = session1.getHttpSessionAttributes().size();
		filter.doFilter(request, response, chain);
		assertThat(session.isInvalid(), equalTo(true));
		assertThrows(IllegalStateException.class, session1::getAuthenticationSessionId);
		AuthenticationSession session2 = new AuthenticationSession(request, newResponse());
		assertThat(session2.getAuthenticationSessionId(), equalTo(authenticationSessionId));
		assertThat(session2.getHttpSessionId(), not(httpSessionId));
		assertThat(session2.getHttpSessionAttributes().size(), equalTo(numAttributes));
	}

	@Test
	public void shouldRedirectToRequestedPageIfAuthenticationFails() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "test");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(authenticationSession.getAuthenticationContext().getCredentials("basic"), nullValue());
		assertThat(response.getRedirectedUrl(), equalTo("/openmrs/patientDashboard.htm"));
	}

	@Test
	public void shouldWhiteListIfAnyPatternsMatchAndGetRequest() {
		AuthenticationConfig.setProperty(AuthenticationConfig.WHITE_LIST, "/login.htm,*.jpg,/**/*.gif");
		request.setMethod("POST");
		request.setRequestURI("/login.htm");
		request.setContextPath("/");
		assertThat(filter.isWhiteListed(request), equalTo(false));
		request.setMethod("GET");
		request.setRequestURI("/login.htm");
		assertThat(filter.isWhiteListed(request), equalTo(true));
		request.setRequestURI("login.htm");
		assertThat(filter.isWhiteListed(request), equalTo(false));
		request.setRequestURI("/loginForm.htm");
		assertThat(filter.isWhiteListed(request), equalTo(false));
		request.setRequestURI("/logo.jpg");
		assertThat(filter.isWhiteListed(request), equalTo(true));
		request.setRequestURI("/resources/module/folder/logo.jpg");
		assertThat(filter.isWhiteListed(request), equalTo(true));
		request.setRequestURI(null);
		request.setServletPath("/logo.gif");
		assertThat(filter.isWhiteListed(request), equalTo(true));
		request.setServletPath("/resources/module/folder/logo.gif");
		assertThat(filter.isWhiteListed(request), equalTo(true));
		request.setServletPath("/logo.png");
		assertThat(filter.isWhiteListed(request), equalTo(false));
		request.setServletPath("/resources/module/folder/logo.png");
		assertThat(filter.isWhiteListed(request), equalTo(false));
	}

	@Test
	public void shouldReturnTrueIfServletPathMatchesPattern() {
		request.setContextPath("/");
		request.setServletPath("/login.htm");
		assertThat(filter.matchesPath(request, "/login.htm"), equalTo(true));
		assertThat(filter.matchesPath(request, "/login.html"), equalTo(false));
	}

	@Test
	public void shouldReturnTrueIfRequestURIMatchesPattern() {
		request.setContextPath("/openmrs");
		request.setRequestURI("/openmrs/login.htm");
		assertThat(filter.matchesPath(request, "/login.htm"), equalTo(true));
		assertThat(filter.matchesPath(request, "login.htm"), equalTo(true));
		assertThat(filter.matchesPath(request, "/openmrs/login.htm"), equalTo(true));
		assertThat(filter.matchesPath(request, "/login.html"), equalTo(false));
	}

	@Test
	public void shouldGetTheDefaultAuthenticationSchemeIfNoneConfigured() {
		AuthenticationScheme scheme = filter.getAuthenticationScheme();
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(UsernamePasswordAuthenticationScheme.class));
	}

	@Test
	public void shouldGetTheConfiguredAuthenticationSchemeIfConfigured() {
		setupTestThatInvokesAuthenticationCheck();
		AuthenticationScheme scheme = filter.getAuthenticationScheme();
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(MockBasicWebAuthenticationScheme.class));
	}

	@Test
	public void shouldRegenerateSession() {
		AuthenticationSession session1 = new AuthenticationSession(request, newResponse());
		String authenticationSessionId = session1.getAuthenticationSessionId();
		String httpSessionId = session1.getHttpSessionId();
		int numAttributes = session1.getHttpSessionAttributes().size();
		filter.regenerateSession(request);
		assertThrows(IllegalStateException.class, session1::getAuthenticationSessionId);
		AuthenticationSession session2 = new AuthenticationSession(request, newResponse());
		assertThat(session2.getAuthenticationSessionId(), equalTo(authenticationSessionId));
		assertThat(session2.getHttpSessionId(), not(httpSessionId));
		assertThat(session2.getHttpSessionAttributes().size(), equalTo(numAttributes));
	}

	@Test
	public void shouldDetermineSuccessUrl() {
		request.setMethod("POST");
		request.setContextPath("/openmrs");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/"));
		request.setRequestURI("/home.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/"));
		request.setMethod("GET");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/home.htm"));
		request.setParameter("refererURL", "/refererPage.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/refererPage.htm"));
		request.setParameter("redirect", "/redirectPage.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/redirectPage.htm"));
	}

	@Test
	public void shouldContextualizeUrl() {
		String expected = "/openmrs/login.htm";
		request.setContextPath("/openmrs");
		assertThat(filter.contextualizeUrl(request, "/login.htm"), equalTo(expected));
		assertThat(filter.contextualizeUrl(request, "login.htm"), equalTo(expected));
		assertThat(filter.contextualizeUrl(request, "/openmrs/login.htm"), equalTo(expected));
		assertThat(filter.contextualizeUrl(request, "/login.html"), not(expected));
	}

	@AfterEach
	@Override
	public void teardown() {
		super.teardown();
		filter.destroy();
	}
}