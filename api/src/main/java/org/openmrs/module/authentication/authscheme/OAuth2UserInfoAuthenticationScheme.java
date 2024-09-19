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

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.ProviderService;
import org.openmrs.api.UserService;
import org.openmrs.api.context.*;
import org.openmrs.module.DaemonToken;
import org.openmrs.module.DaemonTokenAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import static org.openmrs.module.authentication.AuthenticationConfig.AUTH_SCHEME_COMPONENT;

/**
 * A scheme that authenticates with OpenMRS based on the 'username'.
 */
@Transactional
@Component(AUTH_SCHEME_COMPONENT)
public class OAuth2UserInfoAuthenticationScheme extends DaoAuthenticationScheme implements DaemonTokenAware {
	
	protected Log log = LogFactory.getLog(getClass());
	
	private DaemonToken daemonToken;
	
	private AuthenticationPostProcessor postProcessor;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	@Qualifier("providerService")
	private ProviderService ps;
	
	public void setDaemonToken(DaemonToken daemonToken) {
		this.daemonToken = daemonToken;
	}
	
	public void setPostProcessor(AuthenticationPostProcessor postProcessor) {
		this.postProcessor = postProcessor;
	}
	
	public OAuth2UserInfoAuthenticationScheme() {
		setPostProcessor(new AuthenticationPostProcessor() {
			
			@Override
			public void process(UserInfo userInfo) {
				// no post-processing by default
			}
		});
	}
	
	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
		
		OAuth2TokenCredentials creds;
		try {
			creds = (OAuth2TokenCredentials) credentials;
		}
		catch (ClassCastException e) {
			throw new ContextAuthenticationException("The credentials provided did not match those needed for the "
			        + getClass().getSimpleName() + " authentication scheme.", e);
		}
		
		User user = getContextDAO().getUserByUsername(credentials.getClientName());
		if (!creds.isServiceAccount()) {
			if (user == null) {
				createUser(creds.getUserInfo());
			} else {
				updateUser(user, creds.getUserInfo());
			}
			
			postProcessor.process(creds.getUserInfo());
		}
		
		return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
	}
	
	private void createUser(UserInfo userInfo) throws ContextAuthenticationException {
		try {
			getContextDAO().createUser(userInfo.getOpenmrsUser("n/a"), RandomStringUtils.random(100, true, true),
			    userInfo.getRoleNames());
			
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
	
	private void updateUser(User user, UserInfo userInfo) {
		try {
			UpdateUserTask task = new UpdateUserTask(userService, userInfo);
			Daemon.runInDaemonThread(task, daemonToken);
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
}
