/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.UserSessionListener;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationUserSessionListener;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.AuthenticationFilter;
import org.openmrs.module.authentication.web.BasicWebAuthenticationScheme;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;
import org.openmrs.module.authentication.web.mocks.MockTotpAuthenticationScheme;
import org.openmrs.util.Security;
import org.openmrs.web.test.jupiter.BaseModuleWebContextSensitiveTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.util.Collections;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TwoFactorAuthenticationSchemeIntegrationTest extends BaseModuleWebContextSensitiveTest {

	/**
	 * Currently, BaseAuthenticationTest sets an AuthenticationConfig in the global Context but never
	 * cleans it up (test pollution). When this integration test runs afterwards, that leftover
	 * configuration causes OpenMRS to attempt to open a Swing UI credentials dialog. On a server
	 * without a display (like our CI pipelines), this crashes the build with a confusing java.awt.HeadlessException.
	 * This block resets the Context so this test can run safely.
	 */
	private TwoFactorAuthenticationScheme scheme;
	
	@BeforeEach
	void setUp() {
		scheme = new TwoFactorAuthenticationScheme();
	}
	
	@Nested
	@DisplayName("addSecondaryAuthenticationSchemeForUser")
	class AddSecondaryAuthenticationSchemeForUser {
		
		@Test
		@DisplayName("should save the scheme to the database")
		void shouldSaveSchemeToDatabase() {
			User user = Context.getUserService().getUser(1);
			user.getUserProperties().size(); // initialise the lazy collection before detaching
			Context.evictFromSession(user);
			
			scheme.addSecondaryAuthenticationSchemeForUser(user, "totp");
			
			Context.flushSession();
			Context.clearSession();
			
			User savedUser = Context.getUserService().getUser(1);
			String savedProperty = savedUser.getUserProperty(TwoFactorAuthenticationScheme.USER_PROPERTY_SECONDARY_TYPE);
			assertEquals("totp", savedProperty);
		}
	}
	
	@Nested
	@DisplayName("setSecondaryAuthenticationSchemeIdsForUser")
	class SetSecondaryAuthenticationSchemeIdsForUser {
		
		@Test
		@DisplayName("should save the schemes to the database")
		void shouldSaveSchemesToDatabase() {
			User user = Context.getUserService().getUser(1);
			user.getUserProperties().size(); // initialise the lazy collection before detaching
			Context.evictFromSession(user);
			
			scheme.setSecondaryAuthenticationSchemeIdsForUser(user, Collections.singletonList("totp"));
			
			Context.flushSession();
			Context.clearSession();
			
			User savedUser = Context.getUserService().getUser(1);
			String savedProperty = savedUser.getUserProperty(TwoFactorAuthenticationScheme.USER_PROPERTY_SECONDARY_TYPE);
			assertEquals("totp", savedProperty);
		}
	}

	@Nested
	@DisplayName("authenticationWebFlowIntegration")
	class AuthenticationWebFlowIntegration {
		
		@Test
		@DisplayName("should keep user on 2FA page after a wrong TOTP code and allow a successful retry")
		void shouldTestWebFlow() throws Exception {
			User user = Context.getUserService().getUserByUsername("admin");
			scheme.addSecondaryAuthenticationSchemeForUser(user, "totp");
			
			// TotpAuthenticationScheme expects the secret to be encrypted in the database.
			// When validating, it will call Security.decrypt() on this property.
			user.setUserProperty("authentication.totp.secret", Security.encrypt("valid_secret_code"));
			Context.getUserService().saveUser(user);
			
			// BaseModuleWebContextSensitiveTest automatically authenticates as 'admin' before each test.
			// Explicitly log out here so the AuthenticationFilter intercepts our HTTP requests,
			// otherwise it would bypass the filter thinking the user is already fully authenticated.
			Context.logout();
			
			Properties originalProps = Context.getRuntimeProperties();
			// Wrapping the test in a try-finally block to ensure that the mocked Context properties
			// are cleaned up. Otherwise, they leak into other integration tests and cause failures.
			try {
				Properties properties = new Properties();
				properties.putAll(originalProps);
				properties.setProperty("authentication.scheme", "2fa");
				properties.setProperty("authentication.scheme.2fa.type", TwoFactorAuthenticationScheme.class.getName());
				properties.setProperty("authentication.scheme.2fa.config.primaryOptions", "basic");
				properties.setProperty("authentication.scheme.2fa.config.secondaryOptions", "totp");
				
				properties.setProperty("authentication.scheme.basic.type", BasicWebAuthenticationScheme.class.getName());
				properties.setProperty("authentication.scheme.basic.config.loginPage", "/login.htm");
				properties.setProperty("authentication.scheme.basic.config.usernameParam", "username");
				properties.setProperty("authentication.scheme.basic.config.passwordParam", "password");
				
				properties.setProperty("authentication.scheme.totp.type", MockTotpAuthenticationScheme.class.getName());
				properties.setProperty("authentication.scheme.totp.config.loginPage", "/totpLogin.htm");
				properties.setProperty("authentication.scheme.totp.config.codeParam", "code");
				
				AuthenticationConfig.setConfig(properties);
				Context.setRuntimeProperties(properties);
				
				AuthenticationFilter filter = new AuthenticationFilter();
				filter.init(new MockFilterConfig());
				MockHttpSession session = new MockHttpSession();
				MockFilterChain chain;
				
				// Requesting a protected URL (patientDashboard.htm) instead of /login.htm because
				// /login.htm is whitelisted by default. If we POST to a whitelisted URL, the AuthenticationFilter
				// won't redirect us to the secondary challenge URL (/totpLogin.htm).
				MockHttpServletRequest request1 = new MockHttpServletRequest("POST", "/patientDashboard.htm");
				request1.setSession(session);
				request1.setParameter("username", "admin");
				request1.setParameter("password", "test");
				MockHttpServletResponse response1 = new MockHttpServletResponse();
				chain = new MockFilterChain();
				
				filter.doFilter(request1, response1, chain);
				Assertions.assertEquals("/totpLogin.htm", response1.getRedirectedUrl(), "Should redirect to 2FA page after primary success");
				
				MockHttpServletRequest request2 = new MockHttpServletRequest("POST", "/patientDashboard.htm");
				request2.setSession(session);
				request2.setParameter("code", "invalid_secret_code");
				MockHttpServletResponse response2 = new MockHttpServletResponse();
				chain = new MockFilterChain();
				
				filter.doFilter(request2, response2, chain);
				Assertions.assertEquals("/totpLogin.htm", response2.getRedirectedUrl(), "Should redirect back to 2FA page on failure");
				Assertions.assertFalse(Context.isAuthenticated(), "User should not be fully authenticated yet");
				
				MockHttpServletRequest request3 = new MockHttpServletRequest("POST", "/patientDashboard.htm");
				request3.setSession(session);
				request3.setParameter("code", "valid_secret_code");
				MockHttpServletResponse response3 = new MockHttpServletResponse();
				chain = new MockFilterChain();
				
				filter.doFilter(request3, response3, chain);
				Assertions.assertTrue(Context.isAuthenticated(), "User should be fully authenticated");
				Assertions.assertEquals(user, Context.getAuthenticatedUser(), "Authenticated user should match candidate");
			} finally {
				AuthenticationConfig.setConfig(originalProps);
				Context.setRuntimeProperties(originalProps);
			}
		}
	}

	@Nested
	@DisplayName("loginFailureEventIntegration")
	class LoginFailureEventIntegration {
		
		AuthenticationUserSessionListener listener = new AuthenticationUserSessionListener();
		
		@Test
		@DisplayName("should not drop candidate user on secondary auth failure")
		void shouldNotDropCandidateUserOnSecondaryAuthFailure() {
			try {
				User user = Context.getUserService().getUserByUsername("admin");
				
				UserLogin login = new UserLogin();
				login.setUser(user);
				login.authenticationSuccessful("basic", new BasicAuthenticated(user, "basic"));
				UserLoginTracker.setLoginOnThread(login);
				
				// Since session listeners disabled during tests, should manually trigger the login failure event.
				// This simulates what happens when Context.authenticate() fails in the real application.
				listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.FAIL);
				
				// The candidate user should still be retained because primary auth was successful
				Assertions.assertNotNull(login.getUser(), "Candidate user should not be dropped on authentication failure");
			} finally {
				UserLoginTracker.removeLoginFromThread();
			}
		}
	}
}
