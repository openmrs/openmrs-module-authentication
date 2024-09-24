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

/**
 * Represents a set of Test Credentials, primarily to test serialization and deserialization
 */
public class TestAuthenticationCredentials implements AuthenticationCredentials {

    private String schemeId;
    private User user;

    public TestAuthenticationCredentials(String schemeId, User user) {
        this.schemeId = schemeId;
        this.user = user;
    }

    @Override
    public String getAuthenticationScheme() {
        return schemeId;
    }

    @Override
    public String getClientName() {
        return user.getUsername();
    }

    public String getSchemeId() {
        return schemeId;
    }

    public void setSchemeId(String schemeId) {
        this.schemeId = schemeId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
