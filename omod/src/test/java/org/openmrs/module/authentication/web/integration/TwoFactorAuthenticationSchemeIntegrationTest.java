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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;
import org.openmrs.web.test.jupiter.BaseModuleWebContextSensitiveTest;

import java.util.Collections;

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
	@DisplayName("secondaryAuthenticationFailure")
	class SecondaryAuthenticationFailure {
		@Test
		@DisplayName("should retain candidate user if primary authentication succeeds but secondary fails")
		void shouldRetainCandidateUser() {
			User user = Context.getUserService().getUser(1);
			
			UserLogin login = new UserLogin();
			login.setUser(user);
			login.setUsername(user.getUsername());
			login.getValidatedCredentials().add("basic");
			UserLoginTracker.setLoginOnThread(login);
			
			org.openmrs.module.authentication.AuthenticationUserSessionListener listener =
					new org.openmrs.module.authentication.AuthenticationUserSessionListener();
			listener.loggedInOrOut(user, org.openmrs.UserSessionListener.Event.LOGIN, org.openmrs.UserSessionListener.Status.FAIL);
			
			assertEquals(user, login.getUser());
			assertEquals(user.getUsername(), login.getUsername());
			
			UserLoginTracker.removeLoginFromThread();
		}
	}

	@Nested
	@DisplayName("primaryAuthenticationFailure")
	class PrimaryAuthenticationFailure {
		@Test
		@DisplayName("should drop candidate user if primary authentication fails")
		void shouldDropCandidateUser() {
			User user = Context.getUserService().getUser(1);
			
			UserLogin login = new UserLogin();
			login.setUser(user);
			login.setUsername(user.getUsername());
			UserLoginTracker.setLoginOnThread(login);
			
			org.openmrs.module.authentication.AuthenticationUserSessionListener listener =
					new org.openmrs.module.authentication.AuthenticationUserSessionListener();
			listener.loggedInOrOut(user, org.openmrs.UserSessionListener.Event.LOGIN, org.openmrs.UserSessionListener.Status.FAIL);
			
			org.junit.jupiter.api.Assertions.assertNull(login.getUser());
			org.junit.jupiter.api.Assertions.assertNull(login.getUsername());
			UserLoginTracker.removeLoginFromThread();
		}
	}
}
