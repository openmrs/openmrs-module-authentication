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
 * Represents a particular authentication method
 */
public interface Authenticator {

    /**
     * @param instanceName - the unique name that this Authenticator instance is configured with
     * @param config - implementations should use this method to construct an Authenticator instance from configuration
     */
    void configure(String instanceName, Properties config);

    /**
     * Implementations of this method are expected to validate the given AuthenticatorCredentials and return a User
     * If authentication fails, this method should return null
     */
    User authenticate(AuthenticatorCredentials credentials);
}
