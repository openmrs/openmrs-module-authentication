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
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationFilter;
import org.openmrs.module.authentication.web.mocks.MockAuthenticationSession;
import org.openmrs.module.authentication.web.mocks.MockBasicWebAuthenticationScheme;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationFilterTest extends BaseWebAuthenticationTest {

	MockAuthenticationSession authenticationSession;
	MockAuthenticationFilter filter;
	MockFilterChain chain;
	MockHttpSession session;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	User user;
	UserLogin userLogin;

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
		authenticationSession = new MockAuthenticationSession(request, response);
		userLogin = authenticationSession.getUserLogin();
		UserLoginTracker.setLoginOnThread(userLogin);
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
		request.setRequestURI("/patientDashboard.htm");
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
	public void shouldRedirectToChallengeUrlForAuthenticationScheme() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
	}

	@Test
	public void shouldRedirectToSuccessUrlIfAuthenticationSucceeds() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("redirect", "/patientDashboard.htm");
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getRedirectedUrl(), equalTo("/patientDashboard.htm"));
	}

	@Test
	public void shouldRegenerateHttpSessionIfAuthenticationSucceeds() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		assertThat(session.isInvalid(), equalTo(false));
		AuthenticationSession session1 = new AuthenticationSession(request, newResponse());
		UserLogin login1 = session1.getUserLogin();
		String loginId = login1.getLoginId();
		String httpSessionId = login1.getHttpSessionId();
		Map<String, Object> initialAttributes = session1.getHttpSessionAttributes();
		filter.doFilter(request, response, chain);
		assertThat(session.isInvalid(), equalTo(true));
		AuthenticationSession session2 = new AuthenticationSession(request, newResponse());
		UserLogin login2 = session2.getUserLogin();
		assertThat(login2.getLoginId(), equalTo(loginId));
		assertThat(login2.getHttpSessionId(), not(httpSessionId));
		for (String key : initialAttributes.keySet()) {
			Object initialVal = initialAttributes.get(key);
			Object newVal = session2.getHttpSessionAttributes().get(key);
			assertThat(newVal, equalTo(initialVal));
		}
	}

	@Test
	public void shouldRedirectToRequestedPageIfAuthenticationFails() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "test");
		filter.doFilter(request, response, chain);
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(authenticationSession.getUserLogin().getUnvalidatedCredentials("basic"), nullValue());
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
	}

	@Test
	public void shouldWhiteListIfAnyPatternsMatchRequest() {
		AuthenticationConfig.setProperty(AuthenticationConfig.WHITE_LIST, "/login.htm,*.jpg,/**/*.gif");
		request.setContextPath("/");
		request.setRequestURI("/login.htm");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(true));
		request.setRequestURI("login.htm");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(false));
		request.setRequestURI("/loginForm.htm");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(false));
		request.setRequestURI("/logo.jpg");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(true));
		request.setRequestURI("/resources/module/folder/logo.jpg");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(true));
		request.setRequestURI(null);
		request.setServletPath("/logo.gif");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(true));
		request.setServletPath("/resources/module/folder/logo.gif");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(true));
		request.setServletPath("/logo.png");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(false));
		request.setServletPath("/resources/module/folder/logo.png");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(false));
	}

	@Test
	public void shouldReturnTrueIfServletPathMatchesPattern() {
		request.setContextPath("/");
		request.setServletPath("/login.htm");
		assertThat(WebUtil.matchesPath(request, "/login.htm"), equalTo(true));
		assertThat(WebUtil.matchesPath(request, "/login.html"), equalTo(false));
	}

	@Test
	public void shouldReturnTrueIfRequestURIMatchesPattern() {
		request.setContextPath("/openmrs");
		request.setRequestURI("/openmrs/login.htm");
		assertThat(WebUtil.matchesPath(request, "/login.htm"), equalTo(true));
		assertThat(WebUtil.matchesPath(request, "login.htm"), equalTo(true));
		assertThat(WebUtil.matchesPath(request, "/openmrs/login.htm"), equalTo(true));
		assertThat(WebUtil.matchesPath(request, "/login.html"), equalTo(false));
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
	public void shouldDetermineSuccessUrl() {
		request.setMethod("POST");
		request.setContextPath("/openmrs");
		assertThat(filter.determineSuccessRedirectUrl(request), nullValue());
		request.setRequestURI("/home.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), nullValue());
		request.setMethod("GET");
		assertThat(filter.determineSuccessRedirectUrl(request), nullValue());
		request.setParameter("refererURL", "/refererPage.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/refererPage.htm"));
		request.setParameter("redirect", "/redirectPage.htm");
		assertThat(filter.determineSuccessRedirectUrl(request), equalTo("/openmrs/redirectPage.htm"));
	}

	@Test
	public void shouldContextualizeUrl() {
		String expected = "/openmrs/login.htm";
		request.setContextPath("/openmrs");
		assertThat(WebUtil.contextualizeUrl(request, "/login.htm"), equalTo(expected));
		assertThat(WebUtil.contextualizeUrl(request, "login.htm"), equalTo(expected));
		assertThat(WebUtil.contextualizeUrl(request, "/openmrs/login.htm"), equalTo(expected));
		assertThat(WebUtil.contextualizeUrl(request, "/login.html"), not(expected));
	}

	@Test
	public void shouldRedirectIfUrlNotInNonRedirectUrlsPattern() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.NON_REDIRECT_URLS, "/ws/*");
		request.setContextPath("/");
		request.setRequestURI("/patientDashboard.htm");
		filter.handleAuthenticationFailure(request, response, "/login.htm");
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getHeader("Location"), equalTo("/login.htm"));
		assertThat(response.getStatus(), equalTo(HttpServletResponse.SC_MOVED_TEMPORARILY));
	}

	@Test
	public void shouldNotRedirectIfUrlInNonRedirectUrlsPattern() throws Exception {
		AuthenticationConfig.setProperty(AuthenticationConfig.NON_REDIRECT_URLS, "/ws/**/*");
		request.setContextPath("/");
		request.setRequestURI("/ws/fhir2/R4/Patient/923f69ae-fa1a-43db-98e6-bafcc80f5c05");
		filter.handleAuthenticationFailure(request, response, "/login.htm");
		assertThat(response.isCommitted(), equalTo(true));
		assertThat(response.getHeader("Location"), equalTo("/login.htm"));
		assertThat(response.getStatus(), equalTo(HttpServletResponse.SC_UNAUTHORIZED));
	}

	@AfterEach
	@Override
	public void teardown() {
		super.teardown();
		filter.destroy();
		UserLoginTracker.removeLoginFromThread();
	}
}