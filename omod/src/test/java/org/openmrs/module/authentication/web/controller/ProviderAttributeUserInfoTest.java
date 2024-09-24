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
import org.junit.Test;
import org.openmrs.Provider;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.util.PrivilegeConstants;

public class ProviderAttributeUserInfoTest extends OAuth2IntegrationTest {
	
	@Override
	protected String getAppDataDirName() {
		// represents any IdP that allows to pass on the provider attribute as part of the user info JSON
		return "anyidp";
	}
	
	@Override
	protected String getUserInfoJson() {
		return "{\n" + "  \"sub\": \"4e3074d6-5e9f-4707-84f1-ccb2aa2ab3bc\",\n" + "  \"email_verified\": true,\n"
		        + "  \"name\": \"Tommy Atkins\",\n" + "  \"preferred_username\": \"tatkins\",\n"
		        + "  \"given_name\": \"Tommy\",\n" + "  \"family_name\": \"Atkins\",\n"
		        + "  \"email\": \"tatkins@example.com\",\n" + "  \"roles\": [\"Provider\", \"B0gùs Rol3 N@m3\"]\n"
		        + ", \"provider\": \"false\"}";
	}
	
	@Override
	protected void assertAuthenticatedUser(User user) {
		Assert.assertEquals("tatkins", user.getUsername());
		Assert.assertEquals("4e3074d6-5e9f-4707-84f1-ccb2aa2ab3bc", user.getSystemId());
		Assert.assertEquals("Tommy", user.getGivenName());
		Assert.assertEquals("Atkins", user.getFamilyName());
		Assert.assertEquals("tatkins@example.com", user.getEmail());
		assertThatProviderAccountIsDeactivated(user);
	}
	
	@Test
	public void authenticationWithProviderSetAsFalse_shouldDeactivateProviderAccount() throws Exception {
		// setup provider account on user to authenticate
		{
			Context.addProxyPrivilege(PrivilegeConstants.GET_USERS);
			Context.addProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
			
			User user = Context.getUserService().getUserByUsername("tatkins");
			
			Provider provider = new Provider();
			provider.setPerson(user.getPerson());
			provider.setIdentifier(user.getSystemId());
			provider.setCreator(Context.getUserService().getUserByUsername("daemon"));
			Context.getProviderService().saveProvider(provider);
			
			Context.removeProxyPrivilege(PrivilegeConstants.GET_USERS);
			Context.removeProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
			
			// pre-verif
			Assert.assertFalse(Context.isAuthenticated());
			assertThatProviderAccountIsActivated(user);
		}
		
		// replay
		controller.login();
		
		// verif
		User user = Context.getAuthenticatedUser();
		Assert.assertNotNull(user);
		assertAuthenticatedUser(user);
	}
	
	@Override
	protected String[] roleNamesToAssert() {
		return new String[] { "Provider" };
	}
	
}
