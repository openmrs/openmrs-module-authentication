/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.apache.commons.lang.StringUtils;
import org.openmrs.api.context.Context;

import java.io.Serializable;

/**
 * Provides access to data that needs to be shared throughout the authentication process and passed between methods
 */
public class AuthenticationContext implements Serializable {

    private MfaProperties config;
    private MfaUser candidateUser;
    private MfaAuthenticationCredentials credentials;

    public AuthenticationContext(MfaProperties config) {
        this.config = config;
        this.credentials = new MfaAuthenticationCredentials(config);
    }

    // Accessors

    public MfaProperties getConfig() {
        return config;
    }

    public void setConfig(MfaProperties config) {
        this.config = config;
    }

    public MfaUser getCandidateUser() {
        return candidateUser;
    }

    public void setCandidateUser(MfaUser candidateUser) {
        this.candidateUser = candidateUser;
    }

    public MfaAuthenticationCredentials getCredentials() {
        return credentials;
    }

    public void setCredentials(MfaAuthenticationCredentials credentials) {
        this.credentials = credentials;
    }

    // Authentication

    public Authenticator getDefaultPrimaryAuthenticator() {
        return config.getDefaultPrimaryAuthenticator();
    }

    public boolean isPrimaryAuthenticationComplete() {
        return candidateUser != null && getCredentials().getPrimaryCredentials() != null;
    }

    public void setPrimaryAuthenticationComplete(MfaUser candidateUser, AuthenticatorCredentials primaryCredentials) {
        setCandidateUser(candidateUser);
        getCredentials().setPrimaryCredentials(primaryCredentials);
    }

    public Authenticator getSecondaryAuthenticator() {
        Authenticator authenticator = null;
        if (candidateUser != null) {
            String secondaryName = candidateUser.getMfaSecondaryType();
            if (StringUtils.isNotBlank(secondaryName)) {
                authenticator = config.getAuthenticator(secondaryName);
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
