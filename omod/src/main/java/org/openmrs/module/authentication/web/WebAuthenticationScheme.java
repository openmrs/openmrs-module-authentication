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

import org.apache.commons.collections.map.CaseInsensitiveMap;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;

import java.util.Map;

/**
 * Represents a particular method of authentication.
 */
public abstract class WebAuthenticationScheme extends DaoAuthenticationScheme implements ConfigurableAuthenticationScheme {

    public static final String CONFIGURATION_PAGE = "configurationPage";

    private String schemeId;
    private Map<String, String> config;

    /**
     * @return the schemeId that this AuthenticationScheme was configured with
     */
    public String getSchemeId() {
        return schemeId;
    }

    /**
     * @see ConfigurableAuthenticationScheme#configure(String, Map)
     */
    public void configure(String schemeId, Map<String, String> config) {
        this.schemeId = schemeId;
        this.config = config;
    }

    /**
     * @return the properties configured on this instance, or an empty Properties if none configured
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> getConfig() {
        if (config == null) {
            config = new CaseInsensitiveMap();
        }
        return config;
    }

    /**
     * If this AuthenticationScheme requires certain User properties or attributes to be configured, this
     * returns false if the user does not yet have these configured.  Otherwise, returns true
     * @param user the user to check
     * @return false if the user requires additional configuration to use this AuthenticationScheme, false otherwise
     */
    public abstract boolean isUserConfigurationRequired(User user);

    /**
     * @return the page that can be used to configure this AuthenticationScheme for a particular user
     */
    public String getUserConfigurationPage() {
        return config.get(CONFIGURATION_PAGE);
    }

    /**
     * Implementation of authenticate method that notifies UserLogin of successful or failed attempts
     * This method is not intended to be re-implemented
     * Subclasses should instead implement authenticate(AuthenticationCredentials, UserLogin)
     */
    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        if (!(credentials instanceof AuthenticationCredentials)) {
            throw new ContextAuthenticationException("authentication.error.incorrectCredentialsForScheme");
        }
        AuthenticationCredentials authenticationCredentials = (AuthenticationCredentials) credentials;
        String schemeId = authenticationCredentials.getAuthenticationScheme();
        UserLogin userLogin = UserLoginTracker.getLoginOnThread();
        Authenticated authenticated;
        boolean addedToThread = false;
        try {
            if (userLogin == null) {
                userLogin = new UserLogin();
                UserLoginTracker.setLoginOnThread(userLogin);
                addedToThread = true;
            }
            authenticated = authenticate(authenticationCredentials, userLogin);
            userLogin.authenticationSuccessful(schemeId, authenticated);
        }
        catch (Exception e) {
            if (userLogin != null) {
                userLogin.authenticationFailed(schemeId);
            }
            throw new ContextAuthenticationException(e.getMessage(), e);
        }
        finally {
            if (addedToThread) {
                UserLoginTracker.removeLoginFromThread();
            }
        }
        return authenticated;
    }

    /**
     * Subclasses should implement this method with core validation logic
     * @param credentials the credentials to validate
     * @param userLogin the current UserLogin for this AuthenticationSession
     * @return the Authenticated user if successful, null if not
     */
    protected abstract Authenticated authenticate(AuthenticationCredentials credentials, UserLogin userLogin);

    /**
     * This method should return the challenge url at which a user could submit credentials
     * @param session the current AuthenticationSession
     */
    public abstract String getChallengeUrl(AuthenticationSession session);

    /**
     * This method is intended to be used by implementations to inspect the AuthenticationSession and
     * associated session and response for any submitted credentials.  If found, this should construct and
     * return valid AuthenticatorCredentials.  If not found, this should return null.
     * @param session the current AuthenticationSession
     * @return Credentials that could be passed to the authenticate method to attempt authentication or null if none
     */
    public abstract AuthenticationCredentials getCredentials(AuthenticationSession session);

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute prior to each authentication attempt
     */
    public void beforeAuthentication(AuthenticationSession session) {
    }

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute following a successful authentication
     */
    public void afterAuthenticationSuccess(AuthenticationSession session) {
    }

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute following a failed authentication
     */
    public void afterAuthenticationFailure(AuthenticationSession session) {
    }
}
