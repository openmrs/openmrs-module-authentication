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

import org.openmrs.api.context.Credentials;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Interface for all Credentials supported by Authenticator instances.
 * The primary purpose of this class is to extend Credentials by marking them as Serializable
 */
public abstract class AuthenticationCredentials implements Credentials, Serializable {

    private final String schemeId;
    private final Map<String, String> userData;

    public AuthenticationCredentials(String schemeId) {
        this.schemeId = schemeId;
        this.userData = new HashMap<>();
    }

    @Override
    public String toString() {
        return "scheme=" + getAuthenticationScheme() + ", clientName=" + getClientName();
    }

    @Override
    public String getAuthenticationScheme() {
        return schemeId;
    }

    public Map<String, String> getUserData() {
        return userData;
    }
}
