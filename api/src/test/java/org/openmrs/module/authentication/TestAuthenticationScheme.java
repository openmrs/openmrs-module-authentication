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
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;

import java.util.Map;

/**
 * Represents a particular method of authentication.
 */
public class TestAuthenticationScheme implements ConfigurableAuthenticationScheme {

    private String schemeId;
    private Map<String, String> config;

    public TestAuthenticationScheme() {}

    @Override
    public void configure(String schemeId, Map<String, String> config) {
        this.schemeId = schemeId;
        this.config = config;
    }

    @Override
    public Authenticated authenticate(Credentials credentials) {
        String users = (String) config.get("users");
        if (users != null) {
            for (String username : users.split(",")) {
                if (username.equals(credentials.getClientName())) {
                    User user = new User();
                    user.setUsername(username);
                    return new BasicAuthenticated(user, schemeId);
                }
            }
        }
        throw new ContextAuthenticationException("No user " + credentials.getClientName() + " in list.");
    }

    @Override
    public String getSchemeId() {
        return schemeId;
    }

    public Map<String, String> getConfig() {
        return config;
    }
}
