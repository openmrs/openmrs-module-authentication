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

import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.UUID;

/**
 * Wrapper class for an HttpSession that provides access to the AuthenticationContext
 */
public class AuthenticationSession {

    public static final String AUTHENTICATION_SESSION_ID_KEY = "__authentication_session_id";
    public static final String AUTHENTICATION_CONTEXT_KEY = "__authentication_context";
    public static final String AUTHENTICATION_IP_ADDRESS = "__authentication_ip_address";
    public static final String AUTHENTICATION_USERNAME = "__authentication_username";
    public static final String AUTHENTICATION_USER_ID = "__authentication_user_id";

    private final HttpSession session;
    private HttpServletRequest request;

    public AuthenticationSession(HttpSession session) {
        this.session = session;
        AuthenticationLogger.addToContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID, getAuthenticationSessionId());
        AuthenticationLogger.addToContext(AuthenticationLogger.HTTP_SESSION_ID, getHttpSessionId());
        AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, getIpAddress());
        AuthenticationLogger.addToContext(AuthenticationLogger.USERNAME, getUsername());
        AuthenticationLogger.addToContext(AuthenticationLogger.USER_ID, getUserId());
        if (Context.isSessionOpen() && Context.isAuthenticated()) {
            User authenticatedUser = Context.getAuthenticatedUser();
            setUsername(authenticatedUser.getUsername());
            setUserId(authenticatedUser.getUserId().toString());
        }
    }

    public AuthenticationSession(HttpServletRequest request) {
        this(request.getSession());
        this.request = request;
        AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, getIpAddress());
    }

    public AuthenticationContext getAuthenticationContext() {
        AuthenticationContext ctx = (AuthenticationContext) session.getAttribute(AUTHENTICATION_CONTEXT_KEY);
        if (ctx == null) {
            ctx = new AuthenticationContext();
            session.setAttribute(AUTHENTICATION_CONTEXT_KEY, ctx);
        }
        return ctx;
    }

    public String getAuthenticationSessionId() {
        String authSessionId = (String) session.getAttribute(AUTHENTICATION_SESSION_ID_KEY);
        if (authSessionId == null) {
            authSessionId = AuthenticationLogger.getFromContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID);
            if (authSessionId == null) {
                authSessionId = UUID.randomUUID().toString();
            }
            session.setAttribute(AUTHENTICATION_SESSION_ID_KEY, authSessionId);
        }
        return authSessionId;
    }

    public String getIpAddress() {
        String ipAddress = (String)session.getAttribute(AUTHENTICATION_IP_ADDRESS);
        if (ipAddress != null && request != null && !ipAddress.equals(request.getRemoteAddr())) {
            throw new ContextAuthenticationException("IP Address has changed during authentication session");
        }
        if (ipAddress == null) {
            if (request != null) {
                ipAddress = request.getRemoteAddr();
            }
            else {
                ipAddress = AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS);
            }
            session.setAttribute(AUTHENTICATION_IP_ADDRESS, ipAddress);
        }
        return ipAddress;
    }

    public String getUsername() {
        return (String) session.getAttribute(AUTHENTICATION_USERNAME);
    }

    public void setUsername(String username) {
        session.setAttribute(AUTHENTICATION_USERNAME, username);
        AuthenticationLogger.addToContext(AuthenticationLogger.USERNAME, username);
    }

    public String getUserId() {
        return (String) session.getAttribute(AUTHENTICATION_USER_ID);
    }

    public void setUserId(String userId) {
        session.setAttribute(AUTHENTICATION_USER_ID, userId);
        AuthenticationLogger.addToContext(AuthenticationLogger.USER_ID, userId);
    }

    public String getHttpSessionId() {
        return session.getId();
    }

    public String getRequestParam(String name) {
        if (request != null) {
            return request.getParameter(name);
        }
        return null;
    }

    public void removeAuthenticationContext() {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(AUTHENTICATION_CONTEXT_KEY);
        }
    }
}
