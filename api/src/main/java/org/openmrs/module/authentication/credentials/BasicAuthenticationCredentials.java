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

import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordCredentials;

/**
 * AuthenticationCredentials supporting basic authentication - username and password
 */
public class BasicAuthenticationCredentials extends AuthenticationCredentials {

    private String username;
    private String password;

    public BasicAuthenticationCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String getAuthenticationScheme() {
        return UsernamePasswordAuthenticationScheme.class.getName();
    }

    public UsernamePasswordCredentials toUsernamePasswordCredentials() {
        return new UsernamePasswordCredentials(username, password);
    }

    @Override
    public String getClientName() {
        return username;
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
