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
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;
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

/**
 * An AuthenticationSession is typically constructed in the servlet filter via the incoming request, but may also
 * be constructed in HttpSessionListeners that only have access to the session and there is no incoming request.
 * <p>
 * The AuthenticationSession is essentially a wrapper around the HttpSession and the HttpServletRequest (if present),
 * and supports two primary objectives:
 * <p>
 * 1. Manages the lifecycle and provides access to the UserLogin in the HttpSession during the
 * authentication process, to enable workflows to span multiple requests (i.e. two-factor authentication, etc.)
 * 2. Ensures relevant data is added to (and removed from) the UserLogin
 * so that implementations can choose to log information about system authentication as needs evolve.  This
 * information includes the IP Address, Username, UserId, HttpSession ID, and a unique ID that encompasses
 * the user's entire Authentication Session from pre-login HTTP Session creation to post-logout HTTP session destroy
 */
public class AuthenticationSession {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String AUTHENTICATION_USER_LOGIN = "__authentication_user_login";
    public static final String AUTHENTICATION_ERROR_MESSAGE = "__authentication_error_message";
    public static final String AUTHENTICATION_REQUESTED_PAGE = "__authentication_requested_page";
    public static final String AUTHENTICATION_REDIRECT_URL = "__authentication_redirect_url";
    public static final String AUTHENTICATION_REQUESTED_PAGE_TIME = "__authentication_requested_page_time";
    public static final long REQUESTED_PAGE_MAX_AGE_MILLIS = 5L * 60 * 1000;

    private HttpSession session;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private UserLogin userLogin;

    /**
     * This constructor should be used in cases where there is an HttpSession available but not an
     * HttpServletRequest.  Examples of this are in HttpSessionListeners.
     * This constructor sets up data in the HTTP session for tracking authentication details
     * @param session the HttpSession to use to construct this AuthenticationSession
     */
    public AuthenticationSession(HttpSession session) {
        this.session = session;
        userLogin = (UserLogin) session.getAttribute(AUTHENTICATION_USER_LOGIN);
        if (userLogin == null) {
            userLogin = new UserLogin();
            session.setAttribute(AUTHENTICATION_USER_LOGIN, userLogin);
        }
        userLogin.setHttpSessionId(session.getId());
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

        if (userLogin.getIpAddress() != null) {
            if (!userLogin.getIpAddress().equals(request.getRemoteAddr())) {
                log.warn("IP Address change detected: '" + userLogin.getIpAddress() + "' -> '" + request.getRemoteAddr() + "'");
            }
        }
        userLogin.setIpAddress(request.getRemoteAddr());
    }

    /**
     * @return the UserLogin associated with this session
     */
    public UserLogin getUserLogin() {
        return userLogin;
    }

    @Override
    public String toString() {
        return "sessionId="+session.getId()+",loginId="+ userLogin.getLoginId();
    }

    /**
     * @return Map of all attributes in the http session
     */
    @SuppressWarnings("rawtypes")
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
     * @param name the name of the header to return
     * @return the value of the header, or null if the request is null
     */
    public String getRequestHeader(String name) {
        if (request != null) {
            return request.getHeader(name);
        }
        return null;
    }

    /**
     * @return true if there is an open session with an authenticated user
     */
    public boolean isUserAuthenticated() {
        return userLogin.isUserAuthenticated();
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
        }
        catch (Exception e) {
            setErrorMessage(e.getMessage());
            scheme.afterAuthenticationFailure(this);
            throw new ContextAuthenticationException(e.getMessage(), e);
        }
        return authenticated;
    }

    /**
     * Rotates the session id in place using {@code changeSessionId()} to securely guard against session fixation.
     * <p>
     * Note: We specifically do not invalidate and recreate the session here. 
     * Doing so causes the {@code webservices.rest} {@code AuthorizationFilter} 
     * (which runs after this filter on the same request) to answer with a 
     * 401 "Session timed out" because the requested session id would no longer resolve.
     */
    public void regenerateHttpSession() {
        if (request == null) {
            throw new IllegalStateException("Cannot rotate session id without an HttpServletRequest");
        }
        String newSessionId = request.changeSessionId();
        getUserLogin().setHttpSessionId(newSessionId);
        UserLoginTracker.setLoginOnThread(getUserLogin());
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
        else if (getUserLogin().getUser() != null) {
            user = getUserLogin().getUser();
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
     * This mirrors the core functionality to do the same, but ensures the UserLogin is also refreshed
     */
    public void refreshAuthenticatedUser() {
        User authenticatedUser = Context.getAuthenticatedUser();
        User userLoginUser = userLogin.getUser();
        if (userLoginUser != null && userLoginUser.equals(authenticatedUser)) {
            Context.refreshAuthenticatedUser();
            userLogin.setUser(Context.getAuthenticatedUser());
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
     * Records the redirect url requested during a login, to send the user to once authentication succeeds.  This is
     * kept on the session rather than the UserLogin, as login pages may start a new UserLogin when they are displayed.
     * @param redirectUrl the requested redirect url
     */
    public void setRedirectUrl(String redirectUrl) {
        session.setAttribute(AUTHENTICATION_REDIRECT_URL, redirectUrl);
    }

    /**
     * Removes any previously recorded redirect url from the session
     */
    public void removeRedirectUrl() {
        session.removeAttribute(AUTHENTICATION_REDIRECT_URL);
    }

    /**
     * @return the redirect url previously requested during the login
     */
    public String getRedirectUrl() {
        return (String) session.getAttribute(AUTHENTICATION_REDIRECT_URL);
    }

    /**
     * Records the page an unauthenticated user requested before being sent to log in.  This is kept on the
     * session rather than the UserLogin, as login pages may start a new UserLogin when they are displayed.
     * @param requestedPage the requested page, as its request uri and any query string
     */
    public void setRequestedPage(String requestedPage) {
        session.setAttribute(AUTHENTICATION_REQUESTED_PAGE, requestedPage);
        session.setAttribute(AUTHENTICATION_REQUESTED_PAGE_TIME, System.currentTimeMillis());
    }

    /**
     * Removes any previously recorded requested page from the session
     */
    public void removeRequestedPage() {
        session.removeAttribute(AUTHENTICATION_REQUESTED_PAGE);
        session.removeAttribute(AUTHENTICATION_REQUESTED_PAGE_TIME);
    }

    /**
     * @return the page previously recorded as requested before login, unless it was recorded more than
     * REQUESTED_PAGE_MAX_AGE_MILLIS ago, so that an abandoned login doesn't send a later one (perhaps by someone else
     * on a shared computer) to that page
     */
    public String getRequestedPage() {
        Long time = (Long) session.getAttribute(AUTHENTICATION_REQUESTED_PAGE_TIME);
        if (time == null || System.currentTimeMillis() - time > REQUESTED_PAGE_MAX_AGE_MILLIS) {
            removeRequestedPage();
            return null;
        }
        return (String) session.getAttribute(AUTHENTICATION_REQUESTED_PAGE);
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
