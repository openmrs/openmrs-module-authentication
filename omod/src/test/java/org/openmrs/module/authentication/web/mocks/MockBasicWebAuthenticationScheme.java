/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.mocks;

import org.junit.platform.commons.util.StringUtils;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.web.scheme.BasicWebAuthenticationScheme;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public class MockBasicWebAuthenticationScheme extends BasicWebAuthenticationScheme {

    private final Properties usernamesAndPasswords = new Properties();

    public MockBasicWebAuthenticationScheme() {
    }

    @Override
    public void configure(String schemeId, Properties config) {
        super.configure(schemeId, config);
        String prefix = "credential.";
        usernamesAndPasswords.putAll(AuthenticationConfig.getPropertiesWithPrefix(config, prefix, true));
    }

    @Override
    protected Authenticated authenticateWithUsernamePasswordCredentials(UsernamePasswordCredentials credentials) {
        if (StringUtils.isNotBlank(credentials.getUsername())) {
            String password = usernamesAndPasswords.getProperty(credentials.getUsername());
            if (StringUtils.isNotBlank(password) && password.equals(credentials.getPassword())) {
                User user = new User();
                user.setUsername(credentials.getUsername());
                return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
            }
        }
        throw new ContextAuthenticationException("Authentication Failed");
    }
}
