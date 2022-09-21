/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.scheme;

import org.apache.commons.lang.StringUtils;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;
import org.springframework.stereotype.Component;

import static org.openmrs.module.authentication.AuthenticationConfig.AUTHENTICATION_SCHEME;

/**
 * This AuthenticationScheme overrides the core authentication scheme as soon as this module is installed
 * This delegates to another authentication scheme based on configuration, defaulting to the
 * UsernamePasswordAuthenticationScheme if no configuration has been specified
 */
@Component
public class DelegatingAuthenticationScheme implements AuthenticationScheme {

    private AuthenticationScheme authenticationScheme;

    public DelegatingAuthenticationScheme() {
        String scheme = AuthenticationConfig.getProperty(AUTHENTICATION_SCHEME);
        if (StringUtils.isBlank(scheme)) {
            authenticationScheme = new UsernamePasswordAuthenticationScheme();
        }
        else {
            authenticationScheme = AuthenticationConfig.getAuthenticationScheme(scheme);
        }
    }

    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        if (authenticationScheme instanceof UsernamePasswordAuthenticationScheme) {
            if (credentials instanceof BasicAuthenticationCredentials) {
                credentials = ((BasicAuthenticationCredentials) credentials).toUsernamePasswordCredentials();
            }
        }
        return authenticationScheme.authenticate(credentials);
    }

    public AuthenticationScheme getDelegatedAuthenticationScheme() {
        return authenticationScheme;
    }
}
