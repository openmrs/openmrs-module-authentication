/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.openmrs.api.context.AuthenticationScheme;

import java.util.Properties;

/**
 * An authentication scheme that enables configuration from properties
 */
public interface ConfigurableAuthenticationScheme extends AuthenticationScheme {

    /**
     * @return the schemeId that this AuthenticationScheme was configured with
     */
    String getSchemeId();

    /**
     * @param schemeId - the unique schemeId that this AuthenticationScheme instance is registered under
     * @param config - the configuration to use when constructing a new instance of this AuthenticationScheme
     */
    void configure(String schemeId, Properties config);
}
