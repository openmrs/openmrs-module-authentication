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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.UserLogin;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * This is an implementation of a WebAuthenticationScheme that delegates to a UsernamePasswordAuthenticationScheme,
 * and supports basic authentication with a username and password.
 * This scheme supports configuration parameters that enable implementations to utilize it with their own login pages
 * This includes the ability to configure the `loginPage` that the user should be taken to, as well as the
 * `usernameParam` and `passwordParam` that should be read from the http request submission to authenticate.
 */
public class BasicWebAuthenticationScheme extends WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String USERNAME_PARAM = "usernameParam";
    public static final String PASSWORD_PARAM = "passwordParam";

    public static final String DEFAULT_LOGIN_PAGE = "/login.htm";
    public static final String DEFAULT_USERNAME_PARAM = "username";
    public static final String DEFAULT_PASSWORD_PARAM = "password";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    protected String loginPage;
    protected String usernameParam;
    protected String passwordParam;

    /**
     * @see ConfigurableAuthenticationScheme#configure(String, Properties)
     */
    @Override
    public void configure(String schemeId, Properties config) {
        super.configure(schemeId, config);
        loginPage = config.getProperty(LOGIN_PAGE, DEFAULT_LOGIN_PAGE);
        usernameParam = config.getProperty(USERNAME_PARAM, DEFAULT_USERNAME_PARAM);
        passwordParam = config.getProperty(PASSWORD_PARAM, DEFAULT_PASSWORD_PARAM);
    }

    /**
     * @see WebAuthenticationScheme#isUserConfigurationRequired(User) 
     */
    @Override
    public boolean isUserConfigurationRequired(User user) {
        return false;
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
        AuthenticationCredentials credentials = session.getUserLogin().getUnvalidatedCredentials(getSchemeId());
        if (credentials != null) {
            return credentials;
        }
        String username = session.getRequestParam(usernameParam);
        String password = session.getRequestParam(passwordParam);
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            credentials = new BasicCredentials(username, password);
        }
        else {
            String authHeader = session.getRequestHeader(AUTHORIZATION_HEADER);
            if (StringUtils.isNotBlank(authHeader)) {
                // Expected format:  "Basic ${base64encode(username + ":" + password)}"
                try {
                    authHeader = authHeader.substring(6); // remove the leading "Basic "
                    String decodedAuthHeader = new String(Base64.decodeBase64(authHeader), StandardCharsets.UTF_8);
                    String[] userAndPass = decodedAuthHeader.split(":");
                    credentials = new BasicCredentials(userAndPass[0], userAndPass[1]);
                }
                catch (Exception e) {
                    session.setErrorMessage("authentication.error.invalidCredentials");
                    log.warn("Error parsing authentication header", e);
                }
            }
        }

        if (credentials != null) {
            session.getUserLogin().addUnvalidatedCredentials(credentials);
        }
        return credentials;
    }

    /**
     * Extends the authentication scheme to support authentication with UsernamePasswordCredentials, mainly for
     * compatibility with existing clients and modules that pass credentials of this type into the scheme
     * @see BasicWebAuthenticationScheme#authenticate(Credentials)
     */
    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        if (credentials instanceof UsernamePasswordCredentials) {
            UsernamePasswordCredentials upc = (UsernamePasswordCredentials) credentials;
            credentials = new BasicCredentials(upc.getUsername(), upc.getPassword());
        }
        return super.authenticate(credentials);
    }

    /**
     * @see WebAuthenticationScheme#authenticate(AuthenticationCredentials, UserLogin)
     */
    @Override
    public Authenticated authenticate(AuthenticationCredentials credentials, UserLogin userLogin) {
        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof BasicCredentials)) {
            throw new ContextAuthenticationException("authentication.error.incorrectCredentialsForScheme");
        }
        BasicCredentials bac = (BasicCredentials) credentials;
        if (userLogin.getUser() != null && !userLogin.getUser().getUsername().equals(bac.username)) {
            throw new ContextAuthenticationException("authentication.error.userDiffersFromCandidateUser");
        }
        userLogin.setUsername(bac.username);
        UsernamePasswordCredentials upc = new UsernamePasswordCredentials(bac.username, bac.password);
        Authenticated authenticated = authenticateWithUsernamePasswordScheme(upc);
        return new BasicAuthenticated(authenticated.getUser(), getSchemeId());
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
            return getSchemeId();
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
