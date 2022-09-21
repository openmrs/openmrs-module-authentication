/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.credentials;

import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.web.scheme.MultiFactorAuthenticationScheme;

/**
 * Represents the credentials collected during the authentication session
 */
public class MultiFactorAuthenticationCredentials extends AuthenticationCredentials {

    private AuthenticationCredentials primaryCredentials;
    private AuthenticationCredentials secondaryCredentials;

    public MultiFactorAuthenticationCredentials() {
    }

    @Override
    public String getAuthenticationScheme() {
        return MultiFactorAuthenticationScheme.class.getName();
    }

    @Override
    public String getClientName() {
        return (primaryCredentials != null ? primaryCredentials.getClientName() : null);
    }

    public AuthenticationCredentials getPrimaryCredentials() {
        return primaryCredentials;
    }

    public void setPrimaryCredentials(AuthenticationCredentials primaryCredentials) {
        this.primaryCredentials = primaryCredentials;
    }

    public AuthenticationCredentials getSecondaryCredentials() {
        return secondaryCredentials;
    }

    public void setSecondaryCredentials(AuthenticationCredentials secondaryCredentials) {
        this.secondaryCredentials = secondaryCredentials;
    }
}
