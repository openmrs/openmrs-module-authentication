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

import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.springframework.stereotype.Component;

/**
 * This AuthenticationScheme overrides the core authentication scheme as soon as this module is installed
 * This delegates to another authentication scheme based on configuration, defaulting to the
 * UsernamePasswordAuthenticationScheme if no configuration has been specified
 */
@Component
public class DelegatingAuthenticationScheme implements AuthenticationScheme {

    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        AuthenticationScheme authenticationScheme = getDelegatedAuthenticationScheme();
        return authenticationScheme.authenticate(credentials);
    }

    public AuthenticationScheme getDelegatedAuthenticationScheme() {
        return AuthenticationConfig.getAuthenticationScheme();
    }
}
