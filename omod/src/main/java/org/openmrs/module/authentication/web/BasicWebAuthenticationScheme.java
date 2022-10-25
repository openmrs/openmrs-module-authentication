/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.UserLoginTracker;

import java.util.Properties;

/**
 * This is an implementation of a WebAuthenticationScheme that delegates to a UsernamePasswordAuthenticationScheme,
 * and supports basic authentication with a username and password.
 * This scheme supports configuration parameters that enable implementations to utilize it with their own login pages
 * This includes the ability to configure the `loginPage` that the user should be taken to, as well as the
 * `usernameParam` and `passwordParam` that should be read from the http request submission to authenticate.
 */
public class BasicWebAuthenticationScheme implements WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String USERNAME_PARAM = "usernameParam";
    public static final String PASSWORD_PARAM = "passwordParam";

    public static final String DEFAULT_LOGIN_PAGE = "/login.htm";
    public static final String DEFAULT_USERNAME_PARAM = "username";
    public static final String DEFAULT_PASSWORD_PARAM = "password";

    protected String schemeId;
    protected String loginPage;
    protected String usernameParam;
    protected String passwordParam;


    public BasicWebAuthenticationScheme() {
        this.schemeId = getClass().getName();
    }

    /**
     * @return the configured schemeId
     */
    @Override
    public String getSchemeId() {
        return schemeId;
    }

    /**
     * @see ConfigurableAuthenticationScheme#configure(String, Properties)
     */
    @Override
    public void configure(String schemeId, Properties config) {
        this.schemeId = schemeId;
        loginPage = config.getProperty(LOGIN_PAGE, DEFAULT_LOGIN_PAGE);
        usernameParam = config.getProperty(USERNAME_PARAM, DEFAULT_USERNAME_PARAM);
        passwordParam = config.getProperty(PASSWORD_PARAM, DEFAULT_PASSWORD_PARAM);
    }

    /**
     * @see WebAuthenticationScheme#getChallengeUrl(AuthenticationSession)
     */
    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    /**
     * @see WebAuthenticationScheme#getCredentials(AuthenticationSession)
     */
    @Override
    public AuthenticationCredentials getCredentials(AuthenticationSession session) {
        AuthenticationCredentials credentials = session.getUserLogin().getUnvalidatedCredentials(schemeId);
        if (credentials != null) {
            return credentials;
        }
        String username = session.getRequestParam(usernameParam);
        String password = session.getRequestParam(passwordParam);
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            credentials = new BasicCredentials(username, password);
            session.getUserLogin().addUnvalidatedCredentials(credentials);
        }
        return credentials;
    }

    /**
     * @see AuthenticationScheme#authenticate(Credentials)
     */
    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof BasicCredentials)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        BasicCredentials bac = (BasicCredentials) credentials;
        UserLoginTracker.getLoginOnThread().setUsername(bac.username);
        UsernamePasswordCredentials upc = new UsernamePasswordCredentials(bac.username, bac.password);
        Authenticated authenticated = authenticateWithUsernamePasswordScheme(upc);
        return new BasicAuthenticated(authenticated.getUser(), schemeId);
    }

    /**
     * Method to delegate authentication to the UsernamePasswordAuthenticationScheme.
     * This is separated out in a separate method to allow easier mocking
     */
    protected Authenticated authenticateWithUsernamePasswordScheme(UsernamePasswordCredentials credentials) {
        return new UsernamePasswordAuthenticationScheme().authenticate(credentials);
    }

    /**
     * Credentials inner class, to enable access and visibility of credential details to be limited to scheme
     */
    public class BasicCredentials implements AuthenticationCredentials {

        private final String username;
        private final String password;

        @Override
        public String getAuthenticationScheme() {
            return schemeId;
        }

        protected BasicCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public String getClientName() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }
}
