/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
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
import org.openmrs.module.authentication.web.BasicWebAuthenticationScheme;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Represents a particular method of authentication.
 */
public class MockBasicWebAuthenticationScheme extends BasicWebAuthenticationScheme {

    private static final Set<String> validCredentials = new HashSet<>();
    private static final Map<String, User> users = new HashMap<>();

    public MockBasicWebAuthenticationScheme() {
    }

    @Override
    public void configure(String schemeId, Properties config) {
        super.configure(schemeId, config);
        String userConfig = config.getProperty("users");
        if (userConfig != null) {
            for (String username : userConfig.split(",")) {
                String password = config.getProperty("users." + username + ".password");
                String secondaryType = config.getProperty("users." + username + ".secondaryType");
                User user = users.get(username);
                if (user == null) {
                    user = new User();
                    user.setUsername(username);
                    users.put(username, user);
                }
                validCredentials.add(username + ":" + password);
                if (StringUtils.isNotBlank(secondaryType)) {
                    user.setUserProperty("authentication.secondaryType", secondaryType);
                }
            }
        }
    }

    @Override
    protected Authenticated authenticateWithUsernamePasswordScheme(UsernamePasswordCredentials credentials) {
        if (StringUtils.isNotBlank(credentials.getUsername())) {
            if (validCredentials.contains(credentials.getUsername() + ":" + credentials.getPassword())) {
                return new BasicAuthenticated(users.get(credentials.getUsername()), getSchemeId());
            }
        }
        throw new ContextAuthenticationException("Authentication Failed");
    }
}
