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

/**
 * This class is responsible for logging authentication events
 */
public class AuthenticationLogger {

    private static final Logger logger = LogManager.getLogger(AuthenticationLogger.class);

    private static final Marker AUTHENTICATION_EVENT_MARKER = MarkerManager.getMarker("AUTHENTICATION_EVENT");

    public static final String AUTHENTICATION_SESSION_ID = "authenticationSessionId";
    public static final String HTTP_SESSION_ID = "httpSessionId";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";

    public enum Event {
        AUTHENTICATION_MODULE_STARTED,
        AUTHENTICATION_SESSION_CREATED,    
        AUTHENTICATION_PRIMARY_AUTH_SUCCEEDED,
        AUTHENTICATION_PRIMARY_AUTH_FAILED,
        AUTHENTICATION_SECONDARY_AUTH_SUCCEEDED,
        AUTHENTICATION_SECONDARY_AUTH_FAILED,
        AUTHENTICATION_LOGIN_SUCCEEDED,
        AUTHENTICATION_LOGIN_FAILED,
        AUTHENTICATION_LOGOUT_SUCCEEDED,
        AUTHENTICATION_LOGOUT_FAILED,
        AUTHENTICATION_SESSION_DESTROYED,
        AUTHENTICATION_MODULE_STOPPED
    }

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

    public static void removeFromContext(String key) {
        ThreadContext.remove(key);
    }

    public static void clearContext() {
        ThreadContext.clearAll();
    }

    public static void logEvent(Event event, String message) {
        Marker marker = MarkerManager.getMarker(event.name()).setParents(AUTHENTICATION_EVENT_MARKER);
        logger.info(marker, message);
    }

    public static void logEvent(Event event) {
        logEvent(event, event.name());
    }

    public static void logAuthEvent(Event event, AuthenticatorCredentials credentials) {
        logEvent(event, "authenticator=" + credentials.getAuthenticatorName());
    }
}
