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

    // These constants represent available data added to each logging thread. Access with, eg. %X{userId}
    public static final String AUTHENTICATION_SESSION_ID = "authenticationSessionId";
    public static final String HTTP_SESSION_ID = "httpSessionId";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";

    // This is the parent marker for all Markers logged.  Display, along with child markers, as %marker
    public static final Marker AUTHENTICATION_EVENT_MARKER = getMarker("AUTHENTICATION_EVENT");

    // These constants represent individual event markers logged.  Display, without parent, as %markerSimpleName
    public static final Marker MODULE_STARTED = getMarker("AUTHENTICATION_MODULE_STARTED");
    public static final Marker MODULE_STOPPED = getMarker("AUTHENTICATION_MODULE_STOPPED");
    public static final Marker SESSION_CREATED = getMarker("AUTHENTICATION_SESSION_CREATED");
    public static final Marker SESSION_DESTROYED = getMarker("AUTHENTICATION_SESSION_DESTROYED");
    public static final Marker LOGIN_SUCCEEDED = getMarker("AUTHENTICATION_LOGIN_SUCCEEDED");
    public static final Marker LOGIN_FAILED = getMarker("AUTHENTICATION_LOGIN_FAILED");
    public static final Marker LOGOUT_SUCCEEDED = getMarker("AUTHENTICATION_LOGOUT_SUCCEEDED");
    public static final Marker LOGOUT_FAILED = getMarker("AUTHENTICATION_LOGOUT_FAILED");

    /**
     * Convenience method to add username and userId of the given user to the logging context
     * This will remove these from the logging context if the passed user is null
     * @param user the user to add to the logging context
     */
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

    /**
     * Convenience method to remove user specific information (username and userId) from the logging context
     */
    public static void removeUserFromContext() {
        removeFromContext(USERNAME);
        removeFromContext(USER_ID);
    }

    /**
     * Allows adding a specific piece of data to the logging context
     * Anything added to the context will have the passed `value` displayed in the log, if the pattern contains %X{key}
     * @param key the lookup key that can be accessed in the logging pattern with %X{key}
     * @param value the value that will be displayed in the log, if the given key is present in the pattern
     */
    public static void addToContext(String key, String value) {
        ThreadContext.put(key, value);
    }

    /**
     * Allows retrieving a previously added value from the logging context by key
     * @param key the lookup key
     * @return the value in the context for the given key
     */
    public static String getFromContext(String key) {
        return ThreadContext.get(key);
    }

    /**
     * Allows removing a previously added value from the logging context by key
     * @param key the lookup key
     */
    public static void removeFromContext(String key) {
        ThreadContext.remove(key);
    }

    /**
     * Removes all previously added values from the logging context
     */
    public static void clearContext() {
        ThreadContext.clearAll();
    }

    /**
     * Logs a particular message with the given Marker
     * @param marker the Marker to associate with the logging event - accessed with %markerSimpleName
     * @param message the message to associate with the logging event - accessed with %m
     */
    public static void logEvent(Marker marker, String message) {
        logger.info(marker, message);
    }

    /**
     * Logs a particular Marker, with a default message that is the same as the Marker name
     * @param marker the Marker to associate with the logging event - accessed with %markerSimpleName
     */
    public static void logEvent(Marker marker) {
        logEvent(marker, marker.getName());
    }

    /**
     * Retrieve a Marker instance with the given name, with a parent set to the AUTHENTICATION_EVENT marker
     * @param name the name of the Marker to retrieve
     * @return Marker the marker matching the given name, with a parent set to the AUTHENTICATION_EVENT marker
     */
    public static Marker getMarker(String name) {
        return MarkerManager.getMarker(name).setParents(AUTHENTICATION_EVENT_MARKER);
    }
}
