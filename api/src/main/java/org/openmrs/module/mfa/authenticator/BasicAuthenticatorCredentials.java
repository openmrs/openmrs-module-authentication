/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.authenticator;

import org.openmrs.module.mfa.AuthenticatorCredentials;
import org.openmrs.module.mfa.MfaAuthenticationScheme;

/**
 * Interface for all Credentials supported by Authenticator instances.
 */
public class BasicAuthenticatorCredentials implements AuthenticatorCredentials {

    private String authenticatorName;
    private String username;
    private String password;

    public BasicAuthenticatorCredentials(String authenticatorName, String username, String password) {
        this.authenticatorName = authenticatorName;
        this.username = username;
        this.password = password;
    }

    @Override
    public String getAuthenticatorName() {
        return authenticatorName;
    }

    @Override
    public String getAuthenticationScheme() {
        return MfaAuthenticationScheme.class.getName();
    }

    @Override
    public String getClientName() {
        return username;
    }

    public void setAuthenticatorName(String authenticatorName) {
        this.authenticatorName = authenticatorName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
