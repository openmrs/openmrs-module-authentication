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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.util.OpenmrsUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Properties;

/**
 * @see <a href="https://projects.spring.io/spring-security-oauth/docs/oauth2.html">Spring
 *      Documentation</a>
 * @see <a href="https://stackoverflow.com/a/27882337/321797">stackoverflow related question</a>
 */
@EnableOAuth2Client
@Configuration
public class OAuth2BeanFactory {
	
	protected static final Log LOG = LogFactory.getLog(OAuth2BeanFactory.class);
	
	public static Properties getProperties(Path path) throws IOException {
		Properties props = new Properties();
		try(InputStream inputStream=Files.newInputStream(path)) {
			props.load( new InputStreamReader(inputStream, StandardCharsets.UTF_8));
		}
		return props;
	}
	
	public static Path getOAuth2PropertiesPath() {
		Path path = Paths.get(OpenmrsUtil.getApplicationDataDirectory(), "oauth2.properties");
		if (!path.toFile().exists()) {
			LOG.error("the property file doesn't exist " + path.toAbsolutePath());
		}
		return path;
	}
	
	/**
	 * Accessor to the properties files that contains the OAuth 2 client configuration: - client ID
	 * - client secret - user authorization URI - access token URI and - user info URI
	 */
	@Bean(name = "oauth2.properties")
	public Properties getOAuth2Properties() throws IOException {
		return getProperties(getOAuth2PropertiesPath());
	}
	
	@Bean(name = "oauth2.userInfoUri")
	public String getOAuth2UserInfoUri() throws IOException {
		Properties props = getOAuth2Properties();
		return props.getProperty("userInfoUri");
	}
	
	/**
	 * The Spring REST template to transact with the OAuth 2 Resource Provider over HTTP.
	 * 
	 * @param props The OAuth 2 properties (client ID, client secret... etc).
	 * @param oauth2Context Spring Security's client context as driven by @EnableOAuth2Client
	 */
	@Bean(name = "oauth2.restTemplate")
	public RestTemplate getOAuth2RestTemplate(@Qualifier("oauth2.properties") Properties props,
	        OAuth2ClientContext oauth2Context) {
		
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId(props.getProperty("clientId"));
		resource.setClientSecret(props.getProperty("clientSecret"));
		resource.setAccessTokenUri(props.getProperty("accessTokenUri"));
		resource.setUserAuthorizationUri(props.getProperty("userAuthorizationUri"));
		resource.setScope(Arrays.asList(props.getProperty("scope").trim().split(",")));
		
		return new OAuth2RestTemplate(resource, oauth2Context);
	}
}
