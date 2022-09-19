/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.apache.commons.lang.StringUtils;
import org.openmrs.api.context.Context;

import java.io.Serializable;

/**
 * Provides access to data that needs to be shared throughout the authentication process and passed between methods
 */
public class AuthenticationContext implements Serializable {

    private CandidateUser candidateUser;
    private AuthenticationCredentials credentials;

    public AuthenticationContext() {
        this.credentials = new AuthenticationCredentials();
    }

    // Accessors

    public CandidateUser getCandidateUser() {
        return candidateUser;
    }

    public void setCandidateUser(CandidateUser candidateUser) {
        this.candidateUser = candidateUser;
    }

    public AuthenticationCredentials getCredentials() {
        return credentials;
    }

    public void setCredentials(AuthenticationCredentials credentials) {
        this.credentials = credentials;
    }

    // Authentication

    public Authenticator getDefaultPrimaryAuthenticator() {
        return AuthenticationConfig.getDefaultPrimaryAuthenticator();
    }

    public boolean isPrimaryAuthenticationComplete() {
        return candidateUser != null && getCredentials().getPrimaryCredentials() != null;
    }

    public void setPrimaryAuthenticationComplete(CandidateUser candidateUser, AuthenticatorCredentials primaryCredentials) {
        setCandidateUser(candidateUser);
        getCredentials().setPrimaryCredentials(primaryCredentials);
    }

    public Authenticator getSecondaryAuthenticator() {
        Authenticator authenticator = null;
        if (candidateUser != null) {
            String secondaryName = candidateUser.getSecondaryAuthenticationType();
            if (StringUtils.isNotBlank(secondaryName)) {
                authenticator = AuthenticationConfig.getAuthenticator(secondaryName);
            }
        }
        return authenticator;
    }

    public boolean isReadyToAuthenticate() {
        if (Context.isAuthenticated() || !isPrimaryAuthenticationComplete()) {
            return false;
        }
        return getSecondaryAuthenticator() == null || credentials.getSecondaryCredentials() != null;
    }
}
