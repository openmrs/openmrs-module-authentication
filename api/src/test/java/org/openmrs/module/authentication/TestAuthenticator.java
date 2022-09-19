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

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class TestAuthenticator implements Authenticator {

    private String instanceName;
    private Properties config;

    public TestAuthenticator() {}

    @Override
    public void configure(String instanceName, Properties config) {
        this.instanceName = instanceName;
        this.config = new Properties();
    }

    @Override
    public User authenticate(AuthenticatorCredentials credentials) {
        return null;
    }

    public String getInstanceName() {
        return instanceName;
    }

    public void setInstanceName(String instanceName) {
        this.instanceName = instanceName;
    }

    public Properties getConfig() {
        return config;
    }

    public void setConfig(Properties config) {
        this.config = config;
    }
}
