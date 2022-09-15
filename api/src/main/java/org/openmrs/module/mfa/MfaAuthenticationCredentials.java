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

import org.openmrs.api.context.Credentials;

import java.io.Serializable;

/**
 * Represents the credentials collected during the authentication session
 */
public class MfaAuthenticationCredentials implements Credentials, Serializable {

    private AuthenticatorCredentials primaryCredentials;
    private AuthenticatorCredentials secondaryCredentials;

    public MfaAuthenticationCredentials() {
    }

    @Override
    public String getAuthenticationScheme() {
        return MfaAuthenticationScheme.class.getName();
    }

    @Override
    public String getClientName() {
        return (primaryCredentials != null ? primaryCredentials.getClientName() : null);
    }

    public Authenticator getPrimaryAuthenticator() {
        if (primaryCredentials != null && primaryCredentials.getAuthenticatorName() != null) {
            return MfaProperties.getAuthenticator(primaryCredentials.getAuthenticatorName());
        }
        return null;
    }

    public AuthenticatorCredentials getPrimaryCredentials() {
        return primaryCredentials;
    }

    public void setPrimaryCredentials(AuthenticatorCredentials primaryCredentials) {
        this.primaryCredentials = primaryCredentials;
    }

    public Authenticator getSecondaryAuthenticator() {
        if (secondaryCredentials != null && secondaryCredentials.getAuthenticatorName() != null) {
            return MfaProperties.getAuthenticator(secondaryCredentials.getAuthenticatorName());
        }
        return null;
    }

    public AuthenticatorCredentials getSecondaryCredentials() {
        return secondaryCredentials;
    }

    public void setSecondaryCredentials(AuthenticatorCredentials secondaryCredentials) {
        this.secondaryCredentials = secondaryCredentials;
    }
}
