/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;

/**
 * Wrapper class for an HttpSession that provides access to the AuthenticationContext
 */
public class AuthenticationSession {

    public static final String AUTHENTICATION_SESSION_ID_KEY = "__authentication_session_id";
    public static final String AUTHENTICATION_CONTEXT_KEY = "__authentication_context";

    private String authenticationSessionId;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private AuthenticationContext authenticationContext;

    public AuthenticationSession(HttpServletRequest request, HttpServletResponse response) {

        this.request = request;
        this.response = response;

        authenticationContext = (AuthenticationContext) request.getSession().getAttribute(AUTHENTICATION_CONTEXT_KEY);
        if (authenticationContext == null) {
            authenticationContext = new AuthenticationContext();
            request.getSession().setAttribute(AUTHENTICATION_CONTEXT_KEY, authenticationContext);
        }

        authenticationSessionId = (String) request.getSession().getAttribute(AUTHENTICATION_SESSION_ID_KEY);
        if (authenticationSessionId == null) {
            authenticationSessionId = UUID.randomUUID().toString();
            request.getSession().setAttribute(AUTHENTICATION_SESSION_ID_KEY, authenticationSessionId);
        }

        AuthenticationLogger.addToContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID, authenticationSessionId);
        AuthenticationLogger.addToContext(AuthenticationLogger.HTTP_SESSION_ID, request.getSession().getId());
        AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, request.getRemoteAddr());
        if (Context.isSessionOpen()) {
            AuthenticationLogger.addUserToContext(Context.getAuthenticatedUser());
        }
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    public String getRequestParam(String name) {
        return request.getParameter(name);
    }

    public void removeAuthenticationContext() {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(AUTHENTICATION_CONTEXT_KEY);
        }
    }
}
