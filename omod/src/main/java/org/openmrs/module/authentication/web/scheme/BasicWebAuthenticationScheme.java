/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.scheme;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;
import org.openmrs.module.authentication.web.AuthenticationSession;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class BasicWebAuthenticationScheme implements WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String USERNAME_PARAM = "usernameParam";
    public static final String PASSWORD_PARAM = "passwordParam";

    private String instanceName;
    private String loginPage;
    private String usernameParam;
    private String passwordParam;

    public BasicWebAuthenticationScheme() {}

    @Override
    public String getInstanceName() {
        return instanceName;
    }

    @Override
    public void configure(String instanceName, Properties config) {
        this.instanceName = instanceName;
        loginPage = config.getProperty(LOGIN_PAGE, "/module/authentication/basicLogin.htm");
        usernameParam = config.getProperty(USERNAME_PARAM, "username");
        passwordParam = config.getProperty(PASSWORD_PARAM, "password");
    }

    @Override
    public AuthenticationCredentials getCredentials(AuthenticationSession session) {
        BasicAuthenticationCredentials credentials = null;
        String username = session.getRequestParam(usernameParam);
        String password = session.getRequestParam(passwordParam);
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            credentials = new BasicAuthenticationCredentials(username, password);
            session.getAuthenticationContext().setCredentials(getInstanceName(), credentials);
        }
        return credentials;
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        if (session.getAuthenticationContext().getCredentials(getInstanceName()) == null) {
            return loginPage;
        }
        return null;
    }

    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {

        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof BasicAuthenticationCredentials)) {
            throw new ContextAuthenticationException("The credentials provided are invalid.");
        }

        BasicAuthenticationCredentials bac = (BasicAuthenticationCredentials) credentials;
        AuthenticationLogger.addToContext(AuthenticationLogger.USERNAME, bac.getUsername());
        return new UsernamePasswordAuthenticationScheme().authenticate(bac.toUsernamePasswordCredentials());
    }
}
