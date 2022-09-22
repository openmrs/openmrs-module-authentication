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
import org.openmrs.api.context.Credentials;
import org.openmrs.module.authentication.scheme.ConfigurableAuthenticationScheme;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class TestAuthenticationScheme implements ConfigurableAuthenticationScheme {

    private String schemeId;
    private Properties config;

    public TestAuthenticationScheme() {}

    @Override
    public void configure(String schemeId, Properties config) {
        this.schemeId = schemeId;
        this.config = config;
    }

    @Override
    public Authenticated authenticate(Credentials credentials) {
        User user = new User();
        user.setUsername(credentials.getClientName());
        for (String propertyName : config.stringPropertyNames()) {
            user.setUserProperty(propertyName, config.getProperty(propertyName));
        }
        return new BasicAuthenticated(user, schemeId);
    }

    @Override
    public String getSchemeId() {
        return schemeId;
    }

    public Properties getConfig() {
        return config;
    }
}