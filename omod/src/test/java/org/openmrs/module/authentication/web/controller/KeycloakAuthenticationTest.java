/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.controller;

import org.junit.Assert;
import org.openmrs.User;

public class KeycloakAuthenticationTest extends OAuth2IntegrationTest {
	
	@Override
	protected String getAppDataDirName() {
		return "Keycloak";
	}
	
	@Override
	protected String getUserInfoJson() {
		return "{\n" + "  \"sub\": \"4e3074d6-5e9f-4707-84f1-ccb2aa2ab3bc\",\n" + "  \"email_verified\": true,\n"
		        + "  \"name\": \"Tommy Atkins\",\n" + "  \"preferred_username\": \"tatkins\",\n"
		        + "  \"given_name\": \"Tommy\",\n" + "  \"family_name\": \"Atkins\",\n"
		        + "  \"email\": \"tatkins@example.com\",\n" + "  \"roles\": [\"Provider\", \"B0gùs Rol3 N@m3\"]\n" + "}";
	}
	
	@Override
	protected void assertAuthenticatedUser(User user) {
		Assert.assertEquals("tatkins", user.getUsername());
		Assert.assertEquals("4e3074d6-5e9f-4707-84f1-ccb2aa2ab3bc", user.getSystemId());
		Assert.assertEquals("Tommy", user.getGivenName());
		Assert.assertEquals("Atkins", user.getFamilyName());
		Assert.assertEquals("tatkins@example.com", user.getEmail());
		assertThatProviderAccountIsActivated(user);
	}
	
	@Override
	protected String[] roleNamesToAssert() {
		return new String[] { "Provider" };
	}
	
}
