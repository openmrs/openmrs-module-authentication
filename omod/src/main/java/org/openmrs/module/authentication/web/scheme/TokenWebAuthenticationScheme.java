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
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.TokenAuthenticationCredentials;
import org.openmrs.module.authentication.web.AuthenticationSession;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class TokenWebAuthenticationScheme implements WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String TOKEN_PARAM = "tokenParam";

    private String instanceName;
    private String loginPage;
    private String tokenParam;

    public TokenWebAuthenticationScheme() {}

    @Override
    public String getInstanceName() {
        return instanceName;
    }

    @Override
    public void configure(String instanceName, Properties config) {
        this.instanceName = instanceName;
        loginPage = config.getProperty(LOGIN_PAGE, "/module/authentication/token.htm");
        tokenParam = config.getProperty(TOKEN_PARAM, "token");
    }

    @Override
    public AuthenticationCredentials getCredentials(AuthenticationSession session) {
        TokenAuthenticationCredentials credentials = null;
        String token = session.getRequestParam(tokenParam);
        if (StringUtils.isNotBlank(token)) {
            User candidateUser = session.getAuthenticationContext().getCandidateUser();
            credentials = new TokenAuthenticationCredentials(instanceName, candidateUser, token);
        }
        return credentials;
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {

        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof TokenAuthenticationCredentials)) {
            throw new ContextAuthenticationException("The credentials provided are invalid.");
        }

        TokenAuthenticationCredentials tac = (TokenAuthenticationCredentials) credentials;
        // TODO: Temporary to demonstrate.  Replace with proper configuration and algorithm
        if (tac.getToken().equalsIgnoreCase("test")) {
            return new BasicAuthenticated(tac.getCandidateUser(), getInstanceName());
        }
        else {
            throw new ContextAuthenticationException("Invalid token");
        }
    }
}
