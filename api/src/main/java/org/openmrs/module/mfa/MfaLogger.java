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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.util.OpenmrsUtil;

import java.util.Properties;

/**
 * This class is responsible for logging Mfa events
 * This uses the tinylog framework for logging.  Configuration documentation can be found here:
 * <a href="https://tinylog.org/v2/configuration">Configuration</a>
 */
public class MfaLogger {

    private static final Log log = LogFactory.getLog(MfaLogger.class);

    public static final String SESSION_ID = "sessionId";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";

    public enum Event {
        SERVER_STARTED,
        SESSION_CREATED,
        PRIMARY_AUTH_SUCCEEDED,
        PRIMARY_AUTH_FAILED,
        SECONDARY_AUTH_SUCCEEDED,
        SECONDARY_AUTH_FAILED,
        LOGIN_SUCCEEDED,
        LOGIN_FAILED,
        LOGOUT_SUCCEEDED,
        LOGOUT_FAILED,
        SESSION_DESTROYED,
        SERVER_SHUTDOWN
    }

    // Set to true when this class has been initialized from MfaProperties
    private static boolean isInitialized = false;

    public static void initialize() {
        initialize(new MfaProperties());
    }

    /**
     * Initializes logging from mfa.properties.
     * All configuration are prefixed with mfa.logging.<property>=<value>,
     * where <property> and <value> represent valid configuration properties for tinylog
     * @param config
     */
    public static synchronized void initialize(MfaProperties config) {
        if (!isInitialized) {
            Properties loggingProperties = config.getSubsetWithPrefix("logger.", true);
            for (String property : loggingProperties.stringPropertyNames()) {
                String val = loggingProperties.getProperty(property, "");
                val = val.replace("{app-data-dir}", OpenmrsUtil.getApplicationDataDirectory());
                // TODO: Initialize logging framework with property
            }
            isInitialized = true;
        }
        else {
            log.warn("MfaLogger already initialized, not re-initializing");
        }
    }

    public static void addUserToContext(User user) {
        if (user != null) {
            addToContext(USERNAME, StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()));
            addToContext(USER_ID, user.getId());
        }
        else {
            removeUserFromContext();
        }
    }

    public static void removeUserFromContext() {
        removeFromContext(USERNAME);
        removeFromContext(USER_ID);
    }

    public static void addToContext(String key, Object value) {
        // TODO: Add to context
    }

    public static void removeFromContext(String key) {
        // TODO: Remove from context
    }

    public static void clearContext() {
        // TODO: Clear context
    }

    public static void logEvent(Event event, String message) {
        if (!isInitialized) {
            initialize();
        }
        // TODO: Log event message
        log.debug(event.name() + " - " + message);
    }

    public static void logEvent(Event event) {
        logEvent(event, event.name());
    }

    public static void logAuthEvent(Event event, AuthenticatorCredentials credentials) {
        logEvent(event, event.name() + ":" + credentials.getAuthenticatorName());
    }
}
