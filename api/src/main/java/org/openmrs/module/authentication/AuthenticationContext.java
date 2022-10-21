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
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Provides access to authentication details
 * This allows sharing and persisting authentication details across methods, threads, and requests
 * This needs to be serializable is it is typically stored in the HttpSession
 */
public class AuthenticationContext implements Serializable {

    private final String contextId;
    private final Date dateCreated;
    private Date loginDate;
    private Date logoutDate;
    private Date lastActivityDate;
    private String httpSessionId;
    private String ipAddress;
    private String username;
    protected User user;
    private final Map<String, AuthenticationCredentials> unvalidatedCredentials = Collections.synchronizedMap(new HashMap<>());
    private final Set<String> validatedCredentials = Collections.synchronizedSet(new HashSet<>());

    /**
     * Constructs a new Authentication Context with a new contextId
     */
    public AuthenticationContext() {
        contextId = UUID.randomUUID().toString();
        dateCreated = new Date();
    }

    @Override
    public String toString() {
        return "contextId=" + contextId + ",username=" + username;
    }

    /**
     * @return the unique authentication id for this context
     */
    public String getContextId() {
        return contextId;
    }

    /**
     * @return the date this context was created
     */
    public Date getDateCreated() {
        return dateCreated;
    }

    /**
     * @return the login date associated with the context
     */
    public Date getLoginDate() {
        return loginDate;
    }

    /**
     * @param loginDate the date that the user successfully logged into the system
     */
    public synchronized void setLoginDate(Date loginDate) {
        this.loginDate = loginDate;
    }

    /**
     * @return the login date associated with the context
     */
    public Date getLogoutDate() {
        return logoutDate;
    }

    /**
     * @param logoutDate the date that the user logged out of the system
     */
    public synchronized void setLogoutDate(Date logoutDate) {
        this.logoutDate = logoutDate;
    }

    /**
     * @return the last activity date associated with this context
     */
    public Date getLastActivityDate() {
        return lastActivityDate;
    }

    /**
     * @param lastActivityDate the last activity date associated with this context
     */
    public synchronized void setLastActivityDate(Date lastActivityDate) {
        this.lastActivityDate = lastActivityDate;
    }

    /**
     * @return the http session id associated with this context
     */
    public String getHttpSessionId() {
        return httpSessionId;
    }

    /**
     * @param httpSessionId the http Session id associated with this context
     */
    public synchronized void setHttpSessionId(String httpSessionId) {
        this.httpSessionId = httpSessionId;
    }

    /**
     * @return the ip address associated with this context
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * @param ipAddress the ipAddress associated with this context
     */
    public synchronized void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * @return the username associated with this context.  If a user (candidate or otherwise) has been associated
     * with the request, return the username of this user, or their systemId if they do not have a username,
     * otherwise, return the username that was set on this context, generally during initial primary authentication
     */
    public String getUsername() {
        return user != null ? StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()) : username;
    }

    /**
     * @param username the username associated with this context, which can be used to associate this context with
     * a particular user attempting to log in prior to identifying a validated candidate or authenticated user
     */
    public synchronized void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the user associated with this context.  typically this will only be set during the authentication
     * process, by calling the markCredentialAsValid method
     */
    public User getUser() {
        return user;
    }

    /**
     * @param user the user associated with this context.  This is not expected to typically be used directly
     */
    public synchronized void setUser(User user) {
        this.user = user;
    }

    /**
     * @return the userId of the user on the context if present, null otherwise
     */
    public Integer getUserId() {
        return user == null ? null : user.getUserId();
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
     * Marking a set of credentials as valid indicates that these have been validated and removes the
     * credential details from the context
     * @param schemeId the AuthenticationCredentials to mark as valid
     */
    public synchronized void markCredentialsAsValid(String schemeId, User validatedUser) {
        if (validatedUser == null || (user != null && !user.equals(validatedUser))) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        setUser(validatedUser);
        validatedCredentials.add(schemeId);
        unvalidatedCredentials.remove(schemeId);
    }

    /**
     * @param authenticationCredentials the AuthenticationCredentials to remove from the context
     */
    public synchronized void markCredentialsAsInvalid(AuthenticationCredentials authenticationCredentials) {
        unvalidatedCredentials.remove(authenticationCredentials.getAuthenticationScheme());
        if (validatedCredentials.isEmpty()) {
            setUser(null);
        }
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
