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
import org.openmrs.module.mfa.AuthenticatorCredentials;
import org.openmrs.module.mfa.MfaUser;
import org.openmrs.module.mfa.TokenAuthenticationCredentials;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class TokenWebAuthenticator implements WebAuthenticator {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String TOKEN_PARAM = "tokenParam";

    private String instanceName;
    private String loginPage;
    private String tokenParam;

    public TokenWebAuthenticator() {}

    @Override
    public void configure(String instanceName, Properties config) {
        this.instanceName = instanceName;
        loginPage = config.getProperty(LOGIN_PAGE, "/module/mfa/token.htm");
        tokenParam = config.getProperty(TOKEN_PARAM, "token");
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    @Override
    public AuthenticatorCredentials getCredentials(AuthenticationSession session) {
        TokenAuthenticationCredentials credentials = null;
        String token = session.getRequestParam(tokenParam);
        if (StringUtils.isNotBlank(token)) {
            MfaUser candidateUser = session.getAuthenticationContext().getCandidateUser();
            credentials = new TokenAuthenticationCredentials(instanceName, candidateUser, token);
        }
        return credentials;
    }

    @Override
    public User authenticate(AuthenticatorCredentials credentials) {
        User user = null;
        if (credentials != null) {
            if (credentials instanceof TokenAuthenticationCredentials) {
                TokenAuthenticationCredentials tac = (TokenAuthenticationCredentials) credentials;
                // TODO: Temporary to demonstrate.  Replace with proper configuration and algorithm
                if (tac.getToken().equalsIgnoreCase("open sesame")) {
                    user = tac.getMfaUser().getUser();
                }
            }
            else {
                log.warn("Expected " + TokenAuthenticationCredentials.class + " but got " + credentials.getClass());
            }
        }
        return user;
    }
}
