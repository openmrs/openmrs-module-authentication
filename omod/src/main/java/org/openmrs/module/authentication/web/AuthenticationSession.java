/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * An AuthenticationSession is typically constructed in the servlet filter via the incoming request, but may also
 * be constructed in HttpSessionListeners that only have access to the session and there is no incoming request.
 * <p>
 * The AuthenticationSession is essentially a wrapper around the HttpSession and the HttpServletRequest (if present),
 * and supports two primary objectives:
 * <p>
 * 1. Manages the lifecycle and provides access to the AuthenticationContext in the HttpSession during the
 * authentication process, to enable workflows to span multiple requests (i.e. two-factor authentication, etc.)
 * 2. Ensures relevant Authentication data is added to (and removed from) the Logging context
 * so that implementations can choose to log information about system authentication as needs evolve.  This
 * information includes the IP Address, Username, UserId, HttpSession ID, and a unique ID that encompasses
 * the user's entire Authentication Session from pre-login HTTP Session creation to post-logout HTTP session destroy
 */
public class AuthenticationSession {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String AUTHENTICATION_SESSION_ID_KEY = "__authentication_session_id";
    public static final String AUTHENTICATION_CONTEXT_KEY = "__authentication_context";
    public static final String AUTHENTICATION_IP_ADDRESS = "__authentication_ip_address";
    public static final String AUTHENTICATION_USERNAME = "__authentication_username";
    public static final String AUTHENTICATION_USER_ID = "__authentication_user_id";
    public static final String AUTHENTICATION_ERROR_MESSAGE = "__authentication_error_message";

    private HttpSession session;
    private HttpServletRequest request;
    private HttpServletResponse response;

    /**
     * This constructor should be used in cases where there is an HttpSession available but not an
     * HttpServletRequest.  Examples of this are in HttpSessionListeners.
     * This constructor sets up data in the HTTP session for tracking authentication details
     * If a new AuthenticationSession is constructed and a user is already authenticated or there is existing
     * data in the LoggingContext on the current thread, ensure this is initialized
     * @param session the HttpSession to use to construct this AuthenticationSession
     */
    public AuthenticationSession(HttpSession session) {
        this.session = session;
        AuthenticationLogger.addToContext(AuthenticationLogger.AUTHENTICATION_SESSION_ID, getAuthenticationSessionId());
        AuthenticationLogger.addToContext(AuthenticationLogger.HTTP_SESSION_ID, getHttpSessionId());
        AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, getIpAddress());
        AuthenticationLogger.addToContext(AuthenticationLogger.USERNAME, getUsername());
        AuthenticationLogger.addToContext(AuthenticationLogger.USER_ID, getUserId());
        if (isUserAuthenticated()) {
            User authenticatedUser = Context.getAuthenticatedUser();
            setUsername(authenticatedUser.getUsername());
            setUserId(authenticatedUser.getUserId().toString());
        }
    }

    /**
     * This constructor should be used in cases where there is a HttpServletRequest available that contains an
     * HttpSession.  Examples of this would be in Servlet filters and Controllers
     * This constructor sets up data in the HTTP session for tracking authentication details,
     * and makes data from the request available for use in the session (request parameters, IP address, etc)
     * @param request the HttpServletRequest to use to construct this AuthenticationSession
     * @param response the HttpServletResponse to use to construct this AuthenticationSession
     */
    public AuthenticationSession(HttpServletRequest request, HttpServletResponse response) {
        this(request.getSession());
        this.request = request;
        this.response = response;
        AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, getIpAddress());
    }

    /**
     * This will either return the AuthenticationContext stored on the session or a new AuthenticationContext
     * Calling this method will always result in the returned AuthenticationContext stored on the http session
     * @return the AuthenticationContext stored on the session, or a new AuthenticationContext
     */
    public AuthenticationContext getAuthenticationContext() {
        AuthenticationContext ctx = (AuthenticationContext) session.getAttribute(AUTHENTICATION_CONTEXT_KEY);
        if (ctx == null) {
            ctx = new AuthenticationContext();
            session.setAttribute(AUTHENTICATION_CONTEXT_KEY, ctx);
        }
        return ctx;
    }

    /**
     * This returns a unique ID for the authentication session that may span across multiple HTTP sessions,
     * for example when the HTTP session is invalidated and recreated to guard against session fixation, without
     * actually logging out the authenticated user.
     * If no current value exists in the HTTP session, this will check if a value exists on the current thread.
     * If no value exists on either, this will generate a new ID
     * This will store the resulting ID in the session, and then return it.
     * @return the authentication session id for the current authentication session
     */
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

    /**
     * This returns the IP address stored on the current session
     * If no value is found on the session, this will retrieve the IP address from the request
     * If no request is available, this will retrieve the IP address stored on the current thread.
     * This will store the resulting IP Address in the session, and then return it.
     * If there is an IP address on the request, and this differs from the value in the session, a warning is logged
     * @return the authentication session id for the current authentication session
     */
    public String getIpAddress() {
        String sessionIpAddress = (String)session.getAttribute(AUTHENTICATION_IP_ADDRESS);
        String requestIpAddress = (request == null ? null : request.getRemoteAddr());
        if (sessionIpAddress != null && requestIpAddress != null && !sessionIpAddress.equals(requestIpAddress)) {
            log.warn("IP Address change detected from '" + sessionIpAddress + "' to '" + requestIpAddress + "'");
            sessionIpAddress = null;
        }
        if (sessionIpAddress == null) {
            if (requestIpAddress != null) {
                sessionIpAddress = requestIpAddress;
            }
            else {
                sessionIpAddress = AuthenticationLogger.getFromContext(AuthenticationLogger.IP_ADDRESS);
            }
            session.setAttribute(AUTHENTICATION_IP_ADDRESS, sessionIpAddress);
        }
        return sessionIpAddress;
    }

    /**
     * @return the username stored on the session
     */
    public String getUsername() {
        return (String) session.getAttribute(AUTHENTICATION_USERNAME);
    }

    /**
     * This will persist the given username in the HTTP Session and also set it in the Logging context
     * @param username the username to store on the session
     */
    public void setUsername(String username) {
        session.setAttribute(AUTHENTICATION_USERNAME, username);
        AuthenticationLogger.addToContext(AuthenticationLogger.USERNAME, username);
    }

    /**
     * @return the userId stored on the session
     */
    public String getUserId() {
        return (String) session.getAttribute(AUTHENTICATION_USER_ID);
    }

    /**
     * This will persist the given userId in the HTTP Session and also set it in the Logging context
     * @param userId the userId to store on the session
     */
    public void setUserId(String userId) {
        session.setAttribute(AUTHENTICATION_USER_ID, userId);
        AuthenticationLogger.addToContext(AuthenticationLogger.USER_ID, userId);
    }

    /**
     * @return the id of the associated HTTP Session
     */
    public String getHttpSessionId() {
        return session.getId();
    }

    /**
     * @return Map of all attributes in the http session
     */
    public Map<String, Object> getHttpSessionAttributes() {
        Map<String, Object> ret = new HashMap<>();
        Enumeration names = session.getAttributeNames();
        while (names.hasMoreElements()) {
            String attributeName = (String) names.nextElement();
            ret.put(attributeName, session.getAttribute(attributeName));
        }
        return ret;
    }

    /**
     * @return the parameter value found in the associated request, if the request is not null.  Null otherwise.
     */
    public String getRequestParam(String name) {
        if (request != null) {
            return request.getParameter(name);
        }
        return null;
    }

    /**
     * This removes the AuthenticationContext from the HTTP Session
     * Typically this would be called after authentication is complete, to remove any sensitive credential data
     */
    public void removeAuthenticationContext() {
        if (session != null) {
            session.removeAttribute(AUTHENTICATION_CONTEXT_KEY);
        }
    }

    /**
     * This removes all data from the HTTP Session and from the Logging context
     * Typically this would be called when a user is Logged out
     */
    public void destroy() {
        removeAuthenticationContext();
        if (session != null) {
            session.removeAttribute(AUTHENTICATION_SESSION_ID_KEY);
            session.removeAttribute(AUTHENTICATION_IP_ADDRESS);
            session.removeAttribute(AUTHENTICATION_USERNAME);
            session.removeAttribute(AUTHENTICATION_USER_ID);
        }
        AuthenticationLogger.clearContext();
    }

    /**
     * @return true if there is an open session with an authenticated user
     */
    public boolean isUserAuthenticated() {
        return Context.isSessionOpen() && Context.isAuthenticated();
    }

    /**
     * Authenticates the given credentials against the given authentication scheme
     * If this is the main authentication scheme registered with OpenMRS, then authentication is done via the Context
     * This ensures that any authentication hooks are executed before and after the authentication itself
     * @see Context#authenticate(Credentials)
     */
    public Authenticated authenticate(WebAuthenticationScheme scheme, AuthenticationCredentials credentials) {
        Authenticated authenticated;
        try {
            String schemeId = scheme.getSchemeId();
            scheme.beforeAuthentication(this);
            if (schemeId.equals(AuthenticationConfig.getProperty(AuthenticationConfig.SCHEME))) {
                authenticated = Context.authenticate(credentials);
            }
            else {
                authenticated = scheme.authenticate(credentials);
            }
            scheme.afterAuthenticationSuccess(this);
            getAuthenticationContext().addValidatedCredential(schemeId);
        }
        catch (Exception e) {
            scheme.afterAuthenticationFailure(this);
            throw new ContextAuthenticationException(e.getMessage(), e);
        }
        return authenticated;
    }

    /**
     * This regenerates the underlying HTTP Session, by invalidating existing session, and creating a new
     * session that contains the same attributes as the existing session.
     * See:  <a href="https://stackoverflow.com/questions/8162646/how-to-refresh-jsessionid-cookie-after-login">SO</a>
     * See:  <a href="https://owasp.org/www-community/attacks/Session_fixation">Session Fixation</a>
     */
    public void regenerateHttpSession() {
        Properties sessionAttributes = new Properties();
        if (session != null) {
            Enumeration<?> attrNames = session.getAttributeNames();
            if (attrNames != null) {
                while (attrNames.hasMoreElements()) {
                    String attribute = (String) attrNames.nextElement();
                    sessionAttributes.put(attribute, session.getAttribute(attribute));
                }
            }
            session.invalidate();
        }
        session = request.getSession(true);
        Enumeration<Object> attrNames = sessionAttributes.keys();
        if (attrNames != null) {
            while (attrNames.hasMoreElements()) {
                String attribute = (String) attrNames.nextElement();
                session.setAttribute(attribute, sessionAttributes.get(attribute));
            }
        }
    }

    /**
     * This checks whether there is an authenticated or candidate user, and if so,
     * this will set the context locale to this users default locale, and set a cookie to this locale.
     * If there is none, this will look for an existing Cookie value, and if found, will set it as the Context locale
     */
    public void refreshDefaultLocale() {
        Locale locale = null;
        CookieLocaleResolver cookieLocaleResolver = new CookieLocaleResolver();
        User user = null;
        if (isUserAuthenticated()) {
            user = Context.getAuthenticatedUser();
        }
        else if (getAuthenticationContext().getCandidateUser() != null) {
            user = getAuthenticationContext().getCandidateUser();
        }
        if (user != null && Context.isSessionOpen()) {
            locale = Context.getUserService().getDefaultLocaleForUser(user);
            cookieLocaleResolver.setDefaultLocale(locale);
        }
        else if (request != null) {
            locale = cookieLocaleResolver.resolveLocale(request);
        }
        if (Context.isSessionOpen() && locale != null) {
            Context.getUserContext().setLocale(locale);
        }
    }

    /**
     * Sets an attribute on the HttpSession
     * @param key the attribute name
     * @param value the attribute value
     */
    public void setHttpSessionAttribute(String key, Serializable value) {
        session.setAttribute(key, value);
    }

    /**
     * Sets a cookie value on the response, if present
     * @param key the cookie name
     * @param value the cookie value
     */
    public void setCookieValue(String key, String value) {
        if (response != null) {
            response.addCookie(new Cookie(key, value));
        }
    }

    /**
     * Redirects to the given url
     * @param url the url to redirect to
     */
    public void sendRedirect(String url) {
        try {
            response.sendRedirect(url);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * If an exception occurs during Authentication, this stores the details of that on the session
     * @param errorMessage the errorMessage to record
     */
    public void setErrorMessage(String errorMessage) {
        session.setAttribute(AUTHENTICATION_ERROR_MESSAGE, errorMessage);
    }

    /**
     * Removes any previously set error message from the session
     */
    public void removeErrorMessage() {
        session.removeAttribute(AUTHENTICATION_ERROR_MESSAGE);
    }

    /**
     * @return the error message previously set on the session
     */
    public String getErrorMessage() {
        return (String) session.getAttribute(AUTHENTICATION_ERROR_MESSAGE);
    }

    /**
     * @return the HttpSession for this AuthenticationSession
     */
    public HttpSession getHttpSession() {
        return session;
    }

    /**
     * @return the HttpServletRequest for this AuthenticationSession
     */
    public HttpServletRequest getHttpRequest() {
        return request;
    }

    /**
     * @return the HttpServletResponse for this AuthenticationSession
     */
    public HttpServletResponse getHttpResponse() {
        return response;
    }
}
