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

    public Date getLoginDate() {
        return loginDate;
    }

    public synchronized void setLoginDate(Date loginDate) {
        this.loginDate = loginDate;
    }

    public Date getLogoutDate() {
        return logoutDate;
    }

    public synchronized void setLogoutDate(Date logoutDate) {
        this.logoutDate = logoutDate;
    }

    public Date getLastActivityDate() {
        return lastActivityDate;
    }

    public synchronized void setLastActivityDate(Date lastActivityDate) {
        this.lastActivityDate = lastActivityDate;
    }

    public String getHttpSessionId() {
        return httpSessionId;
    }

    public synchronized void setHttpSessionId(String httpSessionId) {
        this.httpSessionId = httpSessionId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public synchronized void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUsername() {
        return user != null ? StringUtils.defaultIfBlank(user.getUsername(), user.getSystemId()) : username;
    }

    public synchronized void setUsername(String username) {
        this.username = username;
    }

    public User getUser() {
        return user;
    }

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
