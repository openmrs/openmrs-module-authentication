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

import java.util.Map;

/**
 * Credentials supporting secondary-authentication.
 */
public class SecondaryAuthenticationCredentials extends AuthenticationCredentials {

    private final User candidateUser;

    public SecondaryAuthenticationCredentials(String schemeId, User candidateUser, Map<String, String> data) {
        super(schemeId);
        this.candidateUser = candidateUser;
        getUserData().putAll(data);
    }

    @Override
    public String getClientName() {
        return candidateUser.getUsername();
    }

    public User getCandidateUser() {
        return candidateUser;
    }
}
