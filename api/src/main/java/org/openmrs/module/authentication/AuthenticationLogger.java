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

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.apache.logging.log4j.ThreadContext;
import org.openmrs.User;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;

/**
 * This class is responsible for logging authentication events
 */
public class AuthenticationLogger {

    private static final Logger logger = LogManager.getLogger(AuthenticationLogger.class);

    public static final String AUTHENTICATION_SESSION_ID = "authenticationSessionId";
    public static final String HTTP_SESSION_ID = "httpSessionId";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";

    public static final Marker AUTHENTICATION_EVENT_MARKER = getMarker("AUTHENTICATION_EVENT");

    public static final Marker MODULE_STARTED = getMarker("AUTHENTICATION_MODULE_STARTED");
    public static final Marker MODULE_STOPPED = getMarker("AUTHENTICATION_MODULE_STOPPED");

    public static final Marker SESSION_CREATED = getMarker("AUTHENTICATION_SESSION_CREATED");
    public static final Marker SESSION_DESTROYED = getMarker("AUTHENTICATION_SESSION_DESTROYED");

    public static final Marker LOGIN_SUCCEEDED = getMarker("AUTHENTICATION_LOGIN_SUCCEEDED");
    public static final Marker LOGIN_FAILED = getMarker("AUTHENTICATION_LOGIN_FAILED");
    public static final Marker LOGOUT_SUCCEEDED = getMarker("AUTHENTICATION_LOGOUT_SUCCEEDED");
    public static final Marker LOGOUT_FAILED = getMarker("AUTHENTICATION_LOGOUT_FAILED");

    public static final Marker PRIMARY_AUTH_SUCCEEDED = getMarker("AUTHENTICATION_PRIMARY_AUTH_SUCCEEDED");
    public static final Marker PRIMARY_AUTH_FAILED = getMarker("AUTHENTICATION_PRIMARY_AUTH_FAILED");
    public static final Marker SECONDARY_AUTH_SUCCEEDED = getMarker("AUTHENTICATION_SECONDARY_AUTH_SUCCEEDED");
    public static final Marker SECONDARY_AUTH_FAILED = getMarker("AUTHENTICATION_SECONDARY_AUTH_FAILED");

    public static void addUserToContext(User user) {
        if (user != null) {
            addToContext(USERNAME, StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()));
            if (user.getUserId() != null) {
                addToContext(USER_ID, user.getId().toString());
            }
        }
        else {
            removeUserFromContext();
        }
    }

    public static void removeUserFromContext() {
        removeFromContext(USERNAME);
        removeFromContext(USER_ID);
    }

    public static void addToContext(String key, String value) {
        ThreadContext.put(key, value);
    }

    public static String getFromContext(String key) {
        return ThreadContext.get(key);
    }

    public static void removeFromContext(String key) {
        ThreadContext.remove(key);
    }

    public static void clearContext() {
        ThreadContext.clearAll();
    }

    public static void logEvent(Marker marker, String message) {
        logger.info(marker, message);
    }

    public static void logEvent(Marker marker) {
        logEvent(marker, marker.getName());
    }

    public static void logAuthEvent(Marker marker, AuthenticationCredentials credentials) {
        logEvent(marker, credentials.toString());
    }

    public static Marker getMarker(String name) {
        return MarkerManager.getMarker(name).setParents(AUTHENTICATION_EVENT_MARKER);
    }
}
