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

import org.apache.commons.lang3.StringUtils;
import org.openmrs.api.context.Context;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Properties;

public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler implements LogoutSuccessHandler {
	
	private OAuth2RestOperations restTemplate;
	
	@Autowired
	public void setRestTemplate(@Qualifier("oauth2.restTemplate") OAuth2RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}
	
	private String getToken() {
		OAuth2AccessToken accessToken = restTemplate.getAccessToken();
		if (accessToken != null) {
			return StringUtils.defaultString(accessToken.getValue());
		}
		return StringUtils.EMPTY;
	}
	
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
	        throws IOException, ServletException {
		Properties properties = OAuth2BeanFactory.getProperties(OAuth2BeanFactory.getOAuth2PropertiesPath());
		String redirectPath = properties.getProperty("logoutUri");
		//the redirect path can contain a [token] that should be replaced by the aut token
		if (StringUtils.isNoneBlank(redirectPath) && redirectPath.contains("[token]")) {
			String token = getToken();
			String encoded = URLEncoder.encode(token, "UTF-8");
			redirectPath = StringUtils.replace(redirectPath, "[token]", encoded);
		}
		Context.logout();
		redirectPath = StringUtils.defaultIfBlank(redirectPath, request.getContextPath() + "/oauth2login");
		super.getRedirectStrategy().sendRedirect(request, response, redirectPath);
	}
	
}
