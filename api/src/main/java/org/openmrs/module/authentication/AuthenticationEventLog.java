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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.apache.logging.log4j.ThreadContext;
import org.openmrs.api.context.AuthenticationScheme;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class is responsible for logging authentication events
 */
public class AuthenticationEventLog {

    private static final Logger log = LogManager.getLogger(AuthenticationEventLog.class);

    // These constants represent available data added to each logging thread. Access with, eg. %X{userId}

    // This is the parent marker for all Markers logged.  Display, along with child markers, as %marker
    public static final Marker AUTHENTICATION_EVENT_MARKER = MarkerManager.getMarker("AUTHENTICATION_EVENT");

    private static final ThreadLocal<AuthenticationContext> threadContext = new ThreadLocal<>();
    private static final Map<String, AuthenticationContext> currentContexts = Collections.synchronizedMap(new LinkedHashMap<>());

    public static void contextInitialized(AuthenticationContext context) {
        threadContext.set(context);
        currentContexts.put(context.getContextId(), context);
    }

    public static void contextDestroyed(AuthenticationContext context) {
        threadContext.remove();
        if (!context.isUserAuthenticated()) {
            currentContexts.remove(context.getContextId());
        }
        ThreadContext.clearAll();
    }

    public static AuthenticationContext getContextForThread() {
        return threadContext.get();
    }

    public static Map<String, AuthenticationContext> getCurrentContexts() {
        return Collections.unmodifiableMap(currentContexts);
    }

    /**
     * @param event the event to log - accessed with %X{event}
     */
    public static void logEvent(AuthenticationEvent event) {
        logEvent(event, null);
    }

    /**
     * @param event the event to log - accessed with %X{event}
     */
    public static void logEvent(AuthenticationEvent event, AuthenticationScheme scheme) {
        if (log.isInfoEnabled()) {
            try {
                AuthenticationContext context = threadContext.get();
                if (context != null) {
                    ThreadContext.put("contextId", context.getContextId());
                    ThreadContext.put("httpSessionId", context.getHttpSessionId());
                    ThreadContext.put("ipAddress", context.getIpAddress());
                    ThreadContext.put("username", context.getUsername());
                    ThreadContext.put("userId", context.getUserId() == null ? null : context.getUserId().toString());
                    ThreadContext.put("event", event.name());
                    if (scheme != null) {
                        ThreadContext.put("schemeType", scheme.getClass().getName());
                        if (scheme instanceof ConfigurableAuthenticationScheme) {
                            ThreadContext.put("schemeId", ((ConfigurableAuthenticationScheme)scheme).getSchemeId());
                        }
                    }
                }
                log.info(AUTHENTICATION_EVENT_MARKER, ThreadContext.getContext().toString());
            }
            finally {
                ThreadContext.clearAll();
            }
        }
    }
}
