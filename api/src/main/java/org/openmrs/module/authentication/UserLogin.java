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
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Represents a particular User Login session and used to track a user's status in the authentication
 * workflow and throughout their usage of the application.  This would typically be stored in the HttpSession
 * in a web-based context.  This needs to be serializable and kept relatively light-weight.
 */
public class UserLogin implements Serializable {

    // This log is used to log all login events
    private static final Logger log = LogManager.getLogger(UserLogin.class);

    // This is the parent marker for all Markers logged.  Display, along with child markers, as %marker
    public static final Marker EVENT_MARKER = MarkerManager.getMarker("AUTHENTICATION_EVENT");

    private final String loginId;
    private final Date dateCreated;
    private Date loginDate;
    private Date logoutDate;
    private Date lastActivityDate;
    private String httpSessionId;
    private String ipAddress;
    private String username;
    private List<AuthenticationEvent> events = new ArrayList<>();
    protected User user;
    private final Map<String, AuthenticationCredentials> unvalidatedCredentials = Collections.synchronizedMap(new HashMap<>());
    private final Set<String> validatedCredentials = Collections.synchronizedSet(new HashSet<>());

    /**
     * Constructs a new instance with a new login id
     */
    public UserLogin() {
        loginId = UUID.randomUUID().toString();
        dateCreated = new Date();
    }

    @Override
    public String toString() {
        return "loginId=" + loginId + ",username=" + username;
    }

    /**
     * @return the unique login id for this user login
     */
    public String getLoginId() {
        return loginId;
    }

    /**
     * @return the date this user login instance was created
     */
    public Date getDateCreated() {
        return dateCreated;
    }

    /**
     * @return the login date if this UserLogin resulted in a successful login to the system
     */
    public Date getLoginDate() {
        return loginDate;
    }

    /**
     * @return the logout date if the user explicitly logged out of this UserLogin
     */
    public Date getLogoutDate() {
        return logoutDate;
    }

    /**
     * @return the last activity date associated with this
     */
    public Date getLastActivityDate() {
        return lastActivityDate;
    }

    /**
     * @param lastActivityDate the last activity date associated with this
     */
    public synchronized void setLastActivityDate(Date lastActivityDate) {
        this.lastActivityDate = lastActivityDate;
    }

    /**
     * @return the http session id associated with this
     */
    public String getHttpSessionId() {
        return httpSessionId;
    }

    /**
     * @param httpSessionId the http Session id associated with this
     */
    public synchronized void setHttpSessionId(String httpSessionId) {
        this.httpSessionId = httpSessionId;
    }

    /**
     * @return the ip address associated with this
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * @param ipAddress the ipAddress associated with this
     */
    public synchronized void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * @return the username associated with this login.  If a user (candidate or otherwise) has been associated
     * with the request, return the username of this user, or their systemId if they do not have a username,
     * otherwise, return the username that was set on this login, generally during initial primary authentication
     */
    public String getUsername() {
        return user != null ? StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()) : username;
    }

    /**
     * @param username the username associated with this login, which can be used to associate this login with
     * a particular user attempting to log in prior to identifying a validated candidate or authenticated user
     */
    public synchronized void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the user associated with this login.  typically this will only be set during the authentication
     * process, by calling the markCredentialAsValid method
     */
    public User getUser() {
        return user;
    }

    /**
     * @param user the user associated with this login.  This is not expected to typically be used directly
     */
    public synchronized void setUser(User user) {
        this.user = user;
    }

    /**
     * @return the userId of the user on the login if present, null otherwise
     */
    public Integer getUserId() {
        return user == null ? null : user.getUserId();
    }

    /**
     * Records a successful authentication
     * @param schemeId the id of the authentication scheme
     * @param authenticated the resulting Authenticated user
     */
    public synchronized void authenticationSuccessful(String schemeId, Authenticated authenticated) {
        if (authenticated.getUser() == null || (user != null && !user.equals(authenticated.getUser()))) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        setUser(authenticated.getUser());
        validatedCredentials.add(schemeId);
        unvalidatedCredentials.remove(schemeId);
        recordEvent(AuthenticationEvent.AUTHENTICATION_SUCCEEDED, schemeId);
    }

    /**
     * Records a failed authentication with the given scheme
     * @param schemeId the id of the authentication scheme that failed
     */
    public synchronized void authenticationFailed(String schemeId) {
        unvalidatedCredentials.remove(schemeId);
        if (validatedCredentials.isEmpty()) {
            setUser(null);
        }
        recordEvent(AuthenticationEvent.AUTHENTICATION_FAILED, schemeId);
    }

    /**
     * Records a successful login into the system
     */
    public synchronized void loginSuccessful() {
        this.loginDate = new Date();
        UserLoginTracker.addActiveLogin(this);
        recordEvent(AuthenticationEvent.LOGIN_SUCCEEDED, null);
    }

    /**
     * Records a failed login into the system
     */
    public synchronized void loginFailed() {
        recordEvent(AuthenticationEvent.LOGIN_FAILED, null);
    }

    /**
     * Records that this user login has expired
     */
    public synchronized void loginExpired() {
        UserLoginTracker.removeActiveLogin(this);
        recordEvent(AuthenticationEvent.LOGIN_EXPIRED, null);
    }

    /**
     * Records a successful logout from the system
     */
    public synchronized void logoutSucceeded() {
        this.logoutDate = new Date();
        UserLoginTracker.removeActiveLogin(this);
        recordEvent(AuthenticationEvent.LOGOUT_SUCCEEDED, null);
    }

    /**
     * Records a failed logout from the system
     */
    public synchronized void logoutFailed() {
        recordEvent(AuthenticationEvent.LOGOUT_FAILED, null);
    }

    /**
     * Adds an authentication event with the given name at the current date/time to the UserLogin
     * This also logs the given AuthenticationEvent using log4j.  This ensures that various data is available in the
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
     * @param schemeId the schemeId that the event refers to, if this corresponds to a specific authentication scheme
     */
    public synchronized void recordEvent(String event, String schemeId) {
        events.add(new AuthenticationEvent(event));
        if (log.isInfoEnabled()) {
            try {
                ThreadContext.put("event", event);
                ThreadContext.put("schemeId", schemeId);
                ThreadContext.put("loginId", getLoginId());
                ThreadContext.put("httpSessionId", getHttpSessionId());
                ThreadContext.put("ipAddress", getIpAddress());
                ThreadContext.put("username", getUsername());
                ThreadContext.put("userId", getUserId() == null ? null : getUserId().toString());
                ThreadContext.put("lastActivityDate", AuthenticationUtil.formatIsoDate(getLastActivityDate()));
                log.info(EVENT_MARKER, ThreadContext.getContext().toString());
            }
            finally {
                ThreadContext.clearAll();
            }
        }
    }

    /**
     * @return the list of AuthenticationEvents associated with this UserLogin
     */
    public List<AuthenticationEvent> getEvents() {
        return events;
    }

    /**
     * @param event the event to check
     * @return true if this contains an event with the given name
     */
    public boolean containsEvent(String event) {
        for (AuthenticationEvent e : getEvents()) {
            if (e.getEvent().equalsIgnoreCase(event)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return true if there is an open session with an authenticated user
     */
    public boolean isUserAuthenticated() {
        return Context.isSessionOpen() && Context.isAuthenticated();
    }

    /**
     * @return the AuthenticationCredentials for the given authentication schemeId
     */
    public AuthenticationCredentials getUnvalidatedCredentials(String schemeId) {
        return unvalidatedCredentials.get(schemeId);
    }

    /**
     * @param authenticationCredentials the AuthenticationCredentials for the given authentication schemeId
     */
    public synchronized void addUnvalidatedCredentials(AuthenticationCredentials authenticationCredentials) {
        unvalidatedCredentials.put(authenticationCredentials.getAuthenticationScheme(), authenticationCredentials);
    }

    /**
     * @param schemeId the schemeId to check if there are existing validated credentials
     * @return true if the credentials for the given schemeId have already been validated
     */
    public boolean isCredentialValidated(String schemeId) {
        return validatedCredentials.contains(schemeId);
    }

    /**
     * @return the set of schemeIds for which validation has not yet occurred
     */
    public Set<String> getUnvalidatedCredentials() {
        return unvalidatedCredentials.keySet();
    }

    /**
     * @return the set of schemeIds for which successful validation has taken place
     */
    public Set<String> getValidatedCredentials() {
        return validatedCredentials;
    }
}
