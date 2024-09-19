/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.controller;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.openmrs.Provider;
import org.openmrs.User;
import org.openmrs.api.ProviderService;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.Credentials;
import org.openmrs.module.DaemonTokenAware;
import org.openmrs.module.TestDaemonToken;
import org.openmrs.module.authentication.authscheme.OAuth2TokenCredentials;
import org.openmrs.module.authentication.authscheme.UserInfo;
import org.openmrs.test.BaseModuleContextSensitiveTest;
import org.openmrs.util.OpenmrsConstants;
import org.openmrs.util.PrivilegeConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

public abstract class OAuth2IntegrationTest extends BaseModuleContextSensitiveTest {
	
	private final static String OPENMRS_APPLICATION_DATA_DIRECTORY = "OPENMRS_APPLICATION_DATA_DIRECTORY";
	
	/**
	 * @return The test app data dir name for the current integration test.
	 */
	protected abstract String getAppDataDirName();
	
	/**
	 * @return The user info JSON response received from the OAuth 2 resource server.
	 */
	protected abstract String getUserInfoJson();
	
	public OAuth2IntegrationTest() {
		super();
		initBaseModuleContext(getAppDataDirName());
		
	}
	
	protected static void initBaseModuleContext(String appDataDirName) {
		initPathInSystemProperties(appDataDirName);
		BaseModuleContextSensitiveTest.runtimeProperties.setProperty(
		    OpenmrsConstants.APPLICATION_DATA_DIRECTORY_RUNTIME_PROPERTY,
		    System.getProperty(OPENMRS_APPLICATION_DATA_DIRECTORY));
		Context.setRuntimeProperties(runtimeProperties);
	}
	
	public static void initPathInSystemProperties(String appDataDirName) {
		String path = normalizePath(OAuth2IntegrationTest.class.getClassLoader().getResource(appDataDirName).getPath());
		System.setProperty(OPENMRS_APPLICATION_DATA_DIRECTORY, path);
	}
	
	private static String normalizePath(String path) {
		//on windows we get /C:/.... so have to replace the first /
		return path.replaceFirst("^/(.:/)", "$1");
	}
	
	@Mock
	private RestOperations testRestTemplate;
	
	@Autowired
	protected OAuth2LoginController controller;
	
	@Autowired
	@Qualifier("oauth2.userInfoUri")
	private String userInfoUri;
	
	private Properties oauth2Props;
	
	@Autowired
	private DaemonTokenAware authenticationScheme;
	
	@Autowired
	@Qualifier("providerService")
	private ProviderService ps;
	
	@Override
	protected Credentials getCredentials() {
		
		try {
			oauth2Props = OAuth2BeanFactory.getProperties(Paths.get(System.getProperty(OPENMRS_APPLICATION_DATA_DIRECTORY),
			    "oauth2.properties"));
		}
		catch (IOException e) {
			e.printStackTrace();
			Assert.fail("The OAuth 2 properties could not be obtained for the authentication test: " + e.getMessage());
		}
		
		return new OAuth2TokenCredentials(new UserInfo(oauth2Props, getUserInfoJson()));
	}
	
	@Before
	public void setup() throws Exception {
		
		new TestDaemonToken().setDaemonToken(authenticationScheme);
		
		controller.setOAuth2Properties(oauth2Props);
		
		controller.setRestTemplate(testRestTemplate);
		when(testRestTemplate.getForObject(eq(new URI(userInfoUri)), eq(String.class))).thenReturn(getUserInfoJson());
		
		//		// Ideally we should do something like this:
		//		User u = Context.getAuthenticatedUser();
		//		Context.becomeUser("daemon");
		//		Context.getUserService().purgeUser(u);
		Context.logout();
	}
	
	protected abstract void assertAuthenticatedUser(User user);
	
	protected abstract String[] roleNamesToAssert();
	
	protected void assertThatProviderAccountIsActivated(User user) {
		Context.addProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
		Collection<Provider> possibleProvider = ps.getProvidersByPerson(user.getPerson(), false);
		Assert.assertThat(possibleProvider, hasSize(1));
		Context.removeProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
	}
	
	protected void assertThatProviderAccountIsDeactivated(User user) {
		Context.addProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
		Collection<Provider> possibleProvider = ps.getProvidersByPerson(user.getPerson(), false);
		Assert.assertThat(possibleProvider, hasSize(0));
		Context.removeProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
	}
	
	@Test
	public void assertOAuth2Authentication() throws Exception {
		// pre-verif
		Assert.assertFalse(Context.isAuthenticated());
		
		// replay
		controller.login();
		
		// verif
		User user = Context.getAuthenticatedUser();
		Assert.assertNotNull(user);
		assertAuthenticatedUser(user);
		Set<String> roleNames = user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet());

		Set<String> expectedRoleNames = new HashSet<>(Arrays.asList(roleNamesToAssert()));
		Assert.assertThat(roleNames, hasSize(CollectionUtils.size(roleNamesToAssert())));
        Assert.assertThat(roleNames, containsInAnyOrder(roleNamesToAssert()));
	}
}
