/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides access to authentication details
 * This allows sharing and persisting authentication details across methods, threads, and requests
 */
public class AuthenticationContext implements Serializable {

    private User candidateUser;
    private final Map<String, AuthenticationCredentials> credentials = new HashMap<>();

    public AuthenticationContext() {
    }

    /**
     * Authenticates the given credentials with OpenMRS
     * This mainly exists to encapsulate this functionality and allow for testing and mocking
     * @see Context#authenticate(Credentials) 
     */
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        return Context.authenticate(credentials);
    }

    // Accessors

    /**
     * @return the candidate User
     */
    public User getCandidateUser() {
        return candidateUser;
    }

    /**
     * @param candidateUser the User to set as the Candidate to authenticate
     */
    public void setCandidateUser(User candidateUser) {
        this.candidateUser = candidateUser;
    }

    /**
     * @return the AuthenticationCredentials for the given authentication schemeId
     */
    public AuthenticationCredentials getCredentials(String schemeId) {
        return credentials.get(schemeId);
    }

    /**
     * @param authenticationCredentials the AuthenticationCredentials for the given authentication schemeId
     */
    public void addCredentials(AuthenticationCredentials authenticationCredentials) {
        credentials.put(authenticationCredentials.getAuthenticationScheme(), authenticationCredentials);
    }

    /**
     * @param schemeId the AuthenticationCredentials to remove from the context
     */
    public void removeCredentials(String schemeId) {
        credentials.remove(schemeId);
    }

    /**
     * @param authenticationCredentials the AuthenticationCredentials to remove from the context
     */
    public void removeCredentials(AuthenticationCredentials authenticationCredentials) {
        removeCredentials(authenticationCredentials.getAuthenticationScheme());
    }
}
