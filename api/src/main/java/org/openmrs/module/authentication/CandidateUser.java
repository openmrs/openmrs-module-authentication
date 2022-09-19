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

import org.apache.commons.lang.StringUtils;
import org.openmrs.User;

import java.io.Serializable;

/**
 * Facade over an OpenMRS user to provide enable access to authentication-related user attributes
 */
public class CandidateUser implements Serializable {

    public static final String AUTHENTICATION = "authentication";
    public static final String SECONDARY_TYPE = "secondaryType";
    public static final String CONFIG = "config";
    private static final String DOT = ".";

    private final User user;

    public CandidateUser(User user) {
        this.user = user;
    }

    public String getSecondaryAuthenticationType() {
        return user.getUserProperty(AUTHENTICATION + DOT + SECONDARY_TYPE);
    }

    public String getAuthenticationConfigProperty(String type, String key) {
        String userProperty = AUTHENTICATION + DOT + CONFIG + DOT + type + DOT + key;
        return user.getUserProperty(userProperty);
    }

    public boolean getAuthenticationConfigPropertyAsBoolean(String type, String key, boolean defaultValue) {
        String val = getAuthenticationConfigProperty(type, key);
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val);
    }

    public void setUserPropertyValue(String type, String key, String value) {
        user.setUserProperty(AUTHENTICATION + DOT + CONFIG + DOT + type + DOT + key, value);
    }

    public User getUser() {
        return user;
    }
}
