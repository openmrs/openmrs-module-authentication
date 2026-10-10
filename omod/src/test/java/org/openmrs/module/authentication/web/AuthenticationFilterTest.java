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

import jakarta.servlet.http.HttpServletResponse;
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
		request.setServletPath("/logo.gif2");
		assertThat(WebUtil.urlMatchesAnyPattern(request, AuthenticationConfig.getWhiteList()), equalTo(false));
		request.setServletPath("/resources/module/folder/logo.png2");
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

	/**
	 * @return a request for a protected page, as an unauthenticated user would make it.  If navigation, it carries the
	 * headers a browser sends when loading a page, otherwise those it sends for a background (fetch or XHR) request
	 */
	private MockHttpServletRequest pageRequest(String method, String uri, String query, boolean navigation) {
		MockHttpServletRequest pageRequest = new MockHttpServletRequest(method, uri);
		pageRequest.setContextPath("/");
		pageRequest.setQueryString(query);
		pageRequest.setSession(session);
		pageRequest.addHeader("Sec-Fetch-Mode", navigation ? "navigate" : "cors");
		pageRequest.addHeader("Sec-Fetch-Dest", navigation ? "document" : "empty");
		return pageRequest;
	}

	/**
	 * @return a browser page load of a protected page, in a webapp deployed at the given context path
	 */
	private MockHttpServletRequest pageRequestAt(String contextPath, String uri, String query) {
		MockHttpServletRequest pageRequest = pageRequest("GET", uri, query, true);
		pageRequest.setContextPath(contextPath);
		return pageRequest;
	}

	@Test
	public void shouldSaveRequestedPageWhenRedirectingToChallengeUrl() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?patientId=2"));
	}

	@Test
	public void shouldRedirectToSavedPageAfterAuthenticationSucceeds() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);

		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		MockHttpServletResponse loginResponse = new MockHttpServletResponse();
		filter.doFilter(request, loginResponse, chain);
		assertThat(loginResponse.getRedirectedUrl(), equalTo("/patientDashboard.htm?patientId=2"));
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldPreferRedirectParameterOverSavedPage() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);

		request.addParameter("redirect", "/home.htm");
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		MockHttpServletResponse loginResponse = new MockHttpServletResponse();
		filter.doFilter(request, loginResponse, chain);
		assertThat(loginResponse.getRedirectedUrl(), equalTo("/home.htm"));
	}

	@Test
	public void shouldReplaceSavedPageWithLaterProtectedPage() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		filter.doFilter(pageRequest("GET", "/findPatient.htm", null, true), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/findPatient.htm"));
	}

	/**
	 * Logging out redirects to the home page, which is saved, as the user is no longer logged in
	 */
	@Test
	public void shouldReplaceHomePageSavedAfterLogoutWithPageRequestedNext() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/", null, true), response, chain);
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?patientId=2"));
	}

	@Test
	public void shouldNotReplaceSavedPageAfterFailedLoginAttempt() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		postToLoginPage("username", "admin", "password", "wrongPassword");
		filter.doFilter(pageRequest("GET", "/index.htm", null, true), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?patientId=2"));
	}

	/**
	 * A post to the login page that isn't a login attempt (eg. an empty form, or a change of language) doesn't lock it
	 */
	@Test
	public void shouldReplaceSavedPageAfterPostToLoginPageWithoutLoginAttempt() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		postToLoginPage();
		filter.doFilter(pageRequest("GET", "/findPatient.htm", null, true), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/findPatient.htm"));
	}

	@Test
	public void shouldReplaceLockedPageWithRedirectRequestedOfTheLoginPage() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		postToLoginPage("username", "admin", "password", "wrongPassword");
		MockHttpServletRequest loginPage = pageRequest("GET", "/login.htm", null, true);
		loginPage.addParameter("redirect", "/owa/myapp/index.html");
		filter.doFilter(loginPage, new MockHttpServletResponse(), new MockFilterChain());
		assertThat(authenticationSession.getRequestedPage(), equalTo("/owa/myapp/index.html"));
		assertThat(authenticationSession.isRequestedPageLocked(), equalTo(false));
	}

	@Test
	public void shouldNotLockWhenNoPageIsSaved() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		postToLoginPage("username", "admin", "password", "wrongPassword");
		filter.doFilter(pageRequest("GET", "/index.htm", null, true), new MockHttpServletResponse(), chain);
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?patientId=2"));
	}

	/**
	 * Posts the given parameter names and values to the login page, as a login attempt.  This uses the request the
	 * authentication session was created with, as schemes read credentials from it, and resets it afterwards.
	 */
	private void postToLoginPage(String... namesAndValues) throws Exception {
		request.setMethod("POST");
		request.setRequestURI("/login.htm");
		for (int i = 0; i < namesAndValues.length; i += 2) {
			request.addParameter(namesAndValues[i], namesAndValues[i + 1]);
		}
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		request.removeAllParameters();
		request.clearAttributes();
		request.setMethod("GET");
	}

	@Test
	public void shouldNotSaveRequestedPageForNonGetRequests() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("POST", "/patientDashboard.htm", null, true), response, chain);
		assertThat(response.getRedirectedUrl(), equalTo("/login.htm"));
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldNotSaveRequestedPageForRequestsThatAreNotPageNavigations() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "fragment=1", false), response, chain);
		MockHttpServletRequest image = new MockHttpServletRequest("GET", "/favicon.ico");
		image.setContextPath("/");
		image.setSession(session);
		image.addHeader("Sec-Fetch-Mode", "no-cors");
		image.addHeader("Sec-Fetch-Dest", "image");
		filter.doFilter(image, new MockHttpServletResponse(), chain);
		MockHttpServletRequest frame = new MockHttpServletRequest("GET", "/patientDashboard.htm");
		frame.setContextPath("/");
		frame.setSession(session);
		frame.addHeader("Sec-Fetch-Mode", "navigate");
		frame.addHeader("Sec-Fetch-Dest", "iframe");
		filter.doFilter(frame, new MockHttpServletResponse(), chain);
		MockHttpServletRequest withoutFetchMetadata = new MockHttpServletRequest("GET", "/patientDashboard.htm");
		withoutFetchMetadata.setContextPath("/");
		withoutFetchMetadata.setSession(session);
		filter.doFilter(withoutFetchMetadata, new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldNotSaveRequestedPageForNonRedirectUrls() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/ws/rest/v1/patient", null, true), response, chain);
		assertThat(response.getStatus(), equalTo(HttpServletResponse.SC_UNAUTHORIZED));
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldSaveAndRedirectToRequestedPageWithContextPath() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/patientDashboard.htm", "patientId=2"), response, chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/openmrs/patientDashboard.htm?patientId=2"));

		request.setContextPath("/openmrs");
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		MockHttpServletResponse loginResponse = new MockHttpServletResponse();
		filter.doFilter(request, loginResponse, chain);
		assertThat(loginResponse.getRedirectedUrl(), equalTo("/openmrs/patientDashboard.htm?patientId=2"));
	}

	@Test
	public void shouldNotSaveLogoutUrls() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/ms/logout", null), response, chain);
		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/logout", null), new MockHttpServletResponse(), chain);
		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/appui/header/logout.action", null), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldNotSavePathsThatWouldRedirectToAnotherHost() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequestAt("", "//evil.example.com/phish", null), response, chain);
		filter.doFilter(pageRequestAt("", "/\\evil.example.com/phish", null), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldIgnoreSavedPageOlderThanFiveMinutes() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/patientDashboard.htm", "patientId=2"), response, chain);
		session.setAttribute(AuthenticationSession.AUTHENTICATION_REQUESTED_PAGE_TIME,
				System.currentTimeMillis() - 6L * 60 * 1000);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
		assertThat(session.getAttribute(AuthenticationSession.AUTHENTICATION_REQUESTED_PAGE), nullValue());

		filter.doFilter(pageRequestAt("/openmrs", "/openmrs/findPatient.htm", null), new MockHttpServletResponse(), chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/openmrs/findPatient.htm"));
	}

	/**
	 * @return a browser page load without fetch metadata, as browsers make over plain http
	 */
	private MockHttpServletRequest pageRequestOverHttp(String uri, String query) {
		MockHttpServletRequest pageRequest = new MockHttpServletRequest("GET", uri);
		pageRequest.setContextPath("/openmrs");
		pageRequest.setQueryString(query);
		pageRequest.setSession(session);
		pageRequest.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		return pageRequest;
	}

	@Test
	public void shouldSaveBrowserPageLoadsWithoutFetchMetadata() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequestOverHttp("/openmrs/patientDashboard.htm", "patientId=2"), response, chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/openmrs/patientDashboard.htm?patientId=2"));
	}

	@Test
	public void shouldNotSaveAjaxRequestsWithoutFetchMetadata() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		MockHttpServletRequest ajax = pageRequestOverHttp("/openmrs/patientDashboard.htm", "fragment=1");
		ajax.addHeader("X-Requested-With", "XMLHttpRequest");
		filter.doFilter(ajax, response, chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldNotSaveEncodedLogoutUrls() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		MockHttpServletRequest encodedLogout = pageRequestAt("/openmrs", "/openmrs/ms/%6Cogout", null);
		encodedLogout.setServletPath("/ms/logout");
		filter.doFilter(encodedLogout, response, chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@Test
	public void shouldNotTakeAProtectedPagesOwnRedirectParameterAsTheLoginRedirect() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		MockHttpServletRequest page = pageRequest("GET", "/patientDashboard.htm", "refererURL=/findPatient.htm", true);
		page.setParameter("refererURL", "/findPatient.htm");
		filter.doFilter(page, response, chain);
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?refererURL=/findPatient.htm"));
	}

	@Test
	public void shouldSaveRedirectRequestedOfTheLoginPageInPlaceOfAPageSavedEarlier() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		MockHttpServletRequest loginPage = pageRequest("GET", "/login.htm", "redirect=/findPatient.htm", true);
		loginPage.setParameter("redirect", "/findPatient.htm");
		filter.doFilter(loginPage, new MockHttpServletResponse(), new MockFilterChain());
		assertThat(authenticationSession.getRequestedPage(), equalTo("/findPatient.htm"));
	}

	@Test
	public void shouldNotSaveRedirectToAnotherHost() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		for (String redirect : new String[] { "//evil.example.com/phish", "/\\evil.example.com/phish",
				"\\\\evil.example.com/phish", "https://evil.example.com/phish", "javascript:alert(1)" }) {
			MockHttpServletRequest loginPage = pageRequest("GET", "/login.htm", null, true);
			loginPage.setParameter("redirect", redirect);
			filter.doFilter(loginPage, new MockHttpServletResponse(), new MockFilterChain());
			assertThat(redirect, authenticationSession.getRequestedPage(), nullValue());
		}
	}

	@Test
	public void shouldNotSaveRedirectThatBrowsersWouldTakeToAnotherHost() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		for (String redirect : new String[] { "/\t/evil.example.com/phish", " //evil.example.com/phish",
				"/\n/evil.example.com/phish", "\u0001//evil.example.com/phish" }) {
			MockHttpServletRequest loginPage = pageRequest("GET", "/login.htm", null, true);
			loginPage.setParameter("redirect", redirect);
			filter.doFilter(loginPage, new MockHttpServletResponse(), new MockFilterChain());
			assertThat(redirect, authenticationSession.getRequestedPage(), nullValue());
		}
	}

	@Test
	public void shouldNotSaveRedirectToLogoutOrNonRedirectUrls() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		for (String redirect : new String[] { "/logout", "/ms/%6Cogout", "/ws/rest/v1/session", "ws/rest/v1/patient",
				"/%77s/rest/v1/session", "/foo/../ws/rest/v1/session", "/ws;x/rest/v1/session", "/../ws/rest/v1/session" }) {
			MockHttpServletRequest loginPage = pageRequest("GET", "/login.htm", null, true);
			loginPage.setParameter("redirect", redirect);
			filter.doFilter(loginPage, new MockHttpServletResponse(), new MockFilterChain());
			assertThat(redirect, authenticationSession.getRequestedPage(), nullValue());
		}
	}

	@Test
	public void shouldNotRedirectToLogoutRequestedWithCredentials() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		request.addParameter("username", "admin");
		request.addParameter("password", "adminPassword");
		request.addParameter("redirect", "/logout");
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl(), nullValue());
	}

	@Test
	public void shouldOnlyTakeRedirectFromTheLoginPage() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		filter.doFilter(pageRequest("GET", "/patientDashboard.htm", "patientId=2", true), response, chain);
		MockHttpServletRequest otherWhitelisted = pageRequest("GET", "/spa/home", "redirect=/findPatient.htm", true);
		otherWhitelisted.setParameter("redirect", "/findPatient.htm");
		filter.doFilter(otherWhitelisted, new MockHttpServletResponse(), new MockFilterChain());
		assertThat(authenticationSession.getRequestedPage(), equalTo("/patientDashboard.htm?patientId=2"));
	}

	@Test
	public void shouldNotSavePagesThatBrowsersPrefetch() throws Exception {
		setupTestThatInvokesAuthenticationCheck();
		MockHttpServletRequest prefetch = pageRequest("GET", "/patientDashboard.htm", "patientId=2", true);
		prefetch.addHeader("Sec-Purpose", "prefetch;prerender");
		filter.doFilter(prefetch, response, chain);
		assertThat(authenticationSession.getRequestedPage(), nullValue());
	}

	@AfterEach
	@Override
	public void teardown() {
		super.teardown();
		filter.destroy();
		UserLoginTracker.removeLoginFromThread();
	}
}