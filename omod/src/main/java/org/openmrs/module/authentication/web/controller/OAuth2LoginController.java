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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.Person;
import org.openmrs.Provider;
import org.openmrs.User;
import org.openmrs.api.PersonService;
import org.openmrs.api.ProviderService;
import org.openmrs.api.UserService;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.authscheme.OAuth2TokenCredentials;
import org.openmrs.module.authentication.authscheme.UserInfo;
import org.openmrs.util.PrivilegeConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestOperations;
import org.springframework.web.servlet.ModelAndView;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Properties;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class OAuth2LoginController {
	
	protected final Log log = LogFactory.getLog(getClass());
	
	private String userInfoUri;
	
	private Properties oauth2Props;
	
	private RestOperations restTemplate; // to fetch user infos from OAuth2 provider
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private PersonService personService;
	
	@Autowired
	@Qualifier("providerService")
	private ProviderService ps;
	
	@Autowired
	public void setRestTemplate(@Qualifier("oauth2.restTemplate") RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}
	
	@Autowired
	public void setOAuth2Properties(@Qualifier("oauth2.properties") Properties oauth2Props) {
		this.oauth2Props = oauth2Props;
	}
	
	@Autowired
	public void setUserInfoUri(@Qualifier("oauth2.userInfoUri") String userInfoUri) {
		this.userInfoUri = userInfoUri;
	}
	
	@RequestMapping(value = "/oauth2login", method = GET)
	public ModelAndView login() {
		
		authenticateWithSpringSecurity();
		String userInfoJson = "{}";
		try {
			userInfoJson = restTemplate.getForObject(new URI(userInfoUri), String.class);
		}
		catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
		
		final UserInfo userInfo = new UserInfo(oauth2Props, userInfoJson);
		try {
			Context.authenticate(new OAuth2TokenCredentials(userInfo));
			if (Context.isAuthenticated()) {
				if ("true".equalsIgnoreCase(userInfo.getString(UserInfo.PROP_PROVIDER, "true"))) {
					activateProviderAccount(Context.getAuthenticatedUser());
				} else {
					deactivateProviderAccount(Context.getAuthenticatedUser());
				}
			}
		}
		catch (ContextAuthenticationException e) {
			log.warn("The user '" + userInfo + "' could not be authenticated with the identity provider.");
			throw e;
		}
		finally {
			log.info("The user '" + userInfo + "' was successfully authenticated with the identity provider.");
		}
		
		return new ModelAndView("redirect:" + getRedirectUri());
	}
	
	private void activateProviderAccount(User user) {
		try {
			Context.addProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
			Context.addProxyPrivilege(PrivilegeConstants.GET_PERSONS);
			Context.addProxyPrivilege(PrivilegeConstants.GET_USERS);
			Context.addProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
			
			Person person = personService.getPerson(user.getPerson().getId());
			Collection<Provider> possibleProvider = ps.getProvidersByPerson(user.getPerson());
			if (possibleProvider.size() == 0) {
				Provider provider = new Provider();
				provider.setIdentifier(user.getSystemId());
				provider.setPerson(person);
				provider.setCreator(userService.getUserByUsername("daemon"));
				ps.saveProvider(provider);
			} else {
				possibleProvider.stream().forEach(provider -> {
					if (provider.getRetired()) ps.unretireProvider(provider);
				});
			}
		}
		catch (Exception e) {
			log.error("Could not create provider account associated with user '" + user.getDisplayString(), e);
		}
		finally {
			Context.removeProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
			Context.removeProxyPrivilege(PrivilegeConstants.GET_PERSONS);
			Context.removeProxyPrivilege(PrivilegeConstants.GET_USERS);
			Context.removeProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
		}
	}
	
	private void deactivateProviderAccount(User user) {
		try {
			Context.addProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
			Context.addProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
			
			Collection<Provider> possibleProvider = ps.getProvidersByPerson(user.getPerson());
			possibleProvider.stream().forEach(provider -> ps.retireProvider(provider, "Disabling provider account by " + AuthenticationConfig.PREFIX));
		}
		catch (Exception e) {
			log.error("Could not retire provider account associated with user '" + user.getDisplayString(), e);
		}
		finally {
			Context.removeProxyPrivilege(PrivilegeConstants.GET_PROVIDERS);
			Context.removeProxyPrivilege(PrivilegeConstants.MANAGE_PROVIDERS);
		}
	}
	
	private String getRedirectUri() {
		final String gpRedirectUri = "oauth2login.redirectUriAfterLogin";
		
		String redirectUri = Context.getAdministrationService().getGlobalProperty(gpRedirectUri);
		final String defaultRedirectUri = "/";
		if (StringUtils.isEmpty(redirectUri)) {
			log.info("Redirecting user to the default URI '" + defaultRedirectUri
			        + "'. This can be changed through the global property '" + gpRedirectUri + "'.");
		} else {
			log.info("Redirecting user to '" + redirectUri + "' as defined by the global property '" + gpRedirectUri + "'.");
		}
		
		return StringUtils.defaultIfBlank(redirectUri, defaultRedirectUri);
	}
	
	private void authenticateWithSpringSecurity() {
		SecurityContextHolder.getContext().setAuthentication(new CustomAuthentication());
	}
	
	/**
	 * Custom authentication used to have the token used by {@link CustomLogoutSuccessHandler} if
	 * needed
	 */
	public static class CustomAuthentication implements Authentication {
		
		@Override
		public String getName() {
			// TODO Check what should be appropriate here
			return "internal";
		}
		
		@Override
		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		}
		
		@Override
		public boolean isAuthenticated() {
			return true;
		}
		
		@Override
		public Object getPrincipal() {
			// TODO Check what should be appropriate here
			return "internal";
		}
		
		/**
		 * @return the token if present
		 */
		@Override
		public Object getDetails() {
			return null;
		}
		
		@Override
		public Object getCredentials() {
			return null;
		}
		
		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return null;
		}
	}
}
