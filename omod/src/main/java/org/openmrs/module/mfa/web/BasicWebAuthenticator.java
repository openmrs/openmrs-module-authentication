/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.mfa.AuthenticatorCredentials;
import org.openmrs.module.mfa.BasicAuthenticatorCredentials;
import org.openmrs.module.mfa.MfaLogger;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class BasicWebAuthenticator implements WebAuthenticator {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String USERNAME_PARAM = "usernameParam";
    public static final String PASSWORD_PARAM = "passwordParam";

    private String instanceName;
    private String loginPage;
    private String usernameParam;
    private String passwordParam;

    public BasicWebAuthenticator() {}

    @Override
    public void configure(String instanceName, Properties config) {
        this.instanceName = instanceName;
        loginPage = config.getProperty(LOGIN_PAGE, "/module/mfa/basicLogin.htm");
        usernameParam = config.getProperty(USERNAME_PARAM, "uname");
        passwordParam = config.getProperty(PASSWORD_PARAM, "pw");
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    @Override
    public AuthenticatorCredentials getCredentials(AuthenticationSession session) {
        BasicAuthenticatorCredentials credentials = null;
        String username = session.getRequestParam(usernameParam);
        String password = session.getRequestParam(passwordParam);
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            credentials = new BasicAuthenticatorCredentials(instanceName, username, password);
        }
        return credentials;
    }

    @Override
    public User authenticate(AuthenticatorCredentials credentials) {
        User user = null;
        if (credentials != null) {
            if (credentials instanceof BasicAuthenticatorCredentials) {
                BasicAuthenticatorCredentials bac = (BasicAuthenticatorCredentials) credentials;
                UsernamePasswordCredentials c = new UsernamePasswordCredentials(bac.getUsername(), bac.getPassword());
                try {
                    MfaLogger.addToContext(MfaLogger.USERNAME, bac.getUsername());
                    Authenticated authenticated = new UsernamePasswordAuthenticationScheme().authenticate(c);
                    user = authenticated.getUser();
                }
                catch (ContextAuthenticationException e) {
                    log.debug("Basic Authentication Failed: " + e.getMessage());
                }
            }
            else {
                log.warn("Expected " + BasicAuthenticatorCredentials.class + " but got " + credentials.getClass());
            }
        }
        return user;
    }
}
