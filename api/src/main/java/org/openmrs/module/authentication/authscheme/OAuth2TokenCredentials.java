/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.authscheme;

import org.openmrs.api.context.Credentials;

/**
 * Credentials consisting of the token received from the OAuth2 identity provider. In practise this
 * token is made of the user info sent over from the OAuth 2 provider.
 */
public class OAuth2TokenCredentials implements Credentials {
	
	final public static String SCHEME_NAME = "USER_TOKEN_AUTH_SCHEME";
	
	private UserInfo userInfo;
	
	private boolean serviceAccount = false;
	
	/**
	 * Builds the credentials from the user info.
	 * 
	 * @param userInfo The OAuth2 user info as an {@link UserInfo} instance.
	 */
	public OAuth2TokenCredentials(UserInfo userInfo) {
		this.userInfo = userInfo;
	}
	
	/**
	 * Builds the credentials from the user info while specifies if the credentials are for a
	 * service account or not
	 * 
	 * @param userInfo The OAuth2 user info as an {@link UserInfo} instance.
	 * @param serviceAccount true if the credentials are for a service account otherwise false
	 */
	public OAuth2TokenCredentials(UserInfo userInfo, boolean serviceAccount) {
		this.userInfo = userInfo;
		this.serviceAccount = serviceAccount;
	}
	
	public UserInfo getUserInfo() {
		return userInfo;
	}
	
	@Override
	public String getAuthenticationScheme() {
		return SCHEME_NAME;
	}
	
	@Override
	public String getClientName() {
		return userInfo.getUsername();
	}
	
	public boolean isServiceAccount() {
		return serviceAccount;
	}
	
}
