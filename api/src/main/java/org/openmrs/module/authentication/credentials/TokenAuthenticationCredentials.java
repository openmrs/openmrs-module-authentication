/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.credentials;

import org.openmrs.User;

/**
 * Credentials supporting token-based authentication.
 * This is generally intended to be used as a secondary authentication factor
 */
public class TokenAuthenticationCredentials extends AuthenticationCredentials {

    private final String schemeId;
    private final User candidateUser;
    private final String token;

    public TokenAuthenticationCredentials(String schemeId, User candidateUser, String token) {
        this.schemeId = schemeId;
        this.candidateUser = candidateUser;
        this.token = token;
    }

    @Override
    public String getAuthenticationScheme() {
        return schemeId;
    }

    @Override
    public String getClientName() {
        return candidateUser.getUsername();
    }

    public User getCandidateUser() {
        return candidateUser;
    }

    public String getToken() {
        return token;
    }
}
