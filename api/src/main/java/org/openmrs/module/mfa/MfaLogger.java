/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.apache.logging.log4j.ThreadContext;
import org.openmrs.User;

/**
 * This class is responsible for logging Mfa events
 */
public class MfaLogger {

    private static final Logger logger = LogManager.getLogger(MfaLogger.class);

    private static final Marker MFA_EVENT_MARKER = MarkerManager.getMarker("MFA_EVENT");

    public static final String SESSION_ID = "sessionId";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";

    public enum Event {
        MFA_MODULE_STARTED,
        MFA_SESSION_CREATED,
        MFA_PRIMARY_AUTH_SUCCEEDED,
        MFA_PRIMARY_AUTH_FAILED,
        MFA_SECONDARY_AUTH_SUCCEEDED,
        MFA_SECONDARY_AUTH_FAILED,
        MFA_LOGIN_SUCCEEDED,
        MFA_LOGIN_FAILED,
        MFA_LOGOUT_SUCCEEDED,
        MFA_LOGOUT_FAILED,
        MFA_SESSION_DESTROYED,
        MFA_MODULE_STOPPED
    }

    public static void addUserToContext(User user) {
        if (user != null) {
            addToContext(USERNAME, StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()));
            addToContext(USER_ID, user.getId().toString());
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
        Marker marker = MarkerManager.getMarker(event.name()).setParents(MFA_EVENT_MARKER);
        logger.info(marker, message);
    }

    public static void logEvent(Event event) {
        logEvent(event, event.name());
    }

    public static void logAuthEvent(Event event, AuthenticatorCredentials credentials) {
        logEvent(event, event.name() + ":" + credentials.getAuthenticatorName());
    }
}
