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

import org.openmrs.User;
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
    private Map<String, AuthenticationCredentials> credentials = new HashMap<>();

    public AuthenticationContext() {
    }

    // Accessors

    public User getCandidateUser() {
        return candidateUser;
    }

    public void setCandidateUser(User candidateUser) {
        this.candidateUser = candidateUser;
    }

    public AuthenticationCredentials getCredentials(String schemeId) {
        return credentials.get(schemeId);
    }

    public void setCredentials(String schemeId, AuthenticationCredentials authenticationCredentials) {
        credentials.put(schemeId, authenticationCredentials);
    }

    public void removeCredentials(String schemeId) {
        credentials.remove(schemeId);
    }

}
