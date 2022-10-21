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

    // Maintains the AuthenticationContext on a given thread.
    private static final ThreadLocal<AuthenticationContext> threadContext = new ThreadLocal<>();

    // Maintains all AuthenticationContext instances that are active (based on session)
    private static final Map<String, AuthenticationContext> currentContexts = Collections.synchronizedMap(new LinkedHashMap<>());

    /**
     * This method should be called in order to register the given AuthenticationContext both on the current
     *  thread and in the list of active AuthenticationContext instances.  Care must be taken when calling this
     *  method to ensure that any context instances added are eventually removed by calling contextDestroyed
     * @param context the AuthenticationContext to add
     */
    public static void contextInitialized(AuthenticationContext context) {
        threadContext.set(context);
        currentContexts.put(context.getContextId(), context);
    }

    /**
     * This method should be called in order to remove the given AuthenticationContext from the current
     *  thread and from the list of active AuthenticationContext instances.  Typically, this method will be called
     *  in conjunction with contextInitialized, either in a `finally` block or similar design that would ensure that
     *  these do not grow to exceed the available memory
     * @param context the AuthenticationContext to remove
     */
    public static void contextDestroyed(AuthenticationContext context) {
        threadContext.remove();
        currentContexts.remove(context.getContextId());
    }

    /**
     * @return the AuthenticationContext that has been associated with the current Thread
     */
    public static AuthenticationContext getContextForThread() {
        return threadContext.get();
    }

    /**
     * @return a Collection of all active AuthenticationContexts, defined as those that are associated with an
     * active session.  The Map returned is keyed on the contextId of the AuthenticationContext
     */
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
     * This logs the given AuthenticationEvent using log4j.  This ensures that various data is available in the
     * logging context to facilitate various logging use cases.  log4j can be used to log events to a file, to
     * the database, or elsewhere, as well as filter events based on the included data.  In a log4j pattern layout,
     * the following are supported in the logging context:
     * <ul>
     *     <li>%X{contextId}</li>
     *     <li>%X{ipAddress}</li>
     *     <li>%X{httpSessionId}</li>
     *     <li>%X{event}</li>
     *     <li>%X{schemeId}</li>
     *     <li>%X{username}</li>
     *     <li>%X{userId}</li>
     * </ul>
     * In addition, all events are logged with a Marker named AUTHENTICATION_EVENT
     * The logged message is a toString representation of all context data listed above
     * @param event the event to log
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
