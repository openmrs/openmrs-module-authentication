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

import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.module.authentication.UserLoginTracker;

import java.util.Properties;

/**
 * Represents a particular method of authentication.
 */
public abstract class WebAuthenticationScheme extends DaoAuthenticationScheme implements ConfigurableAuthenticationScheme {

    private String schemeId;
    private Properties config;

    /**
     * @return the schemeId that this AuthenticationScheme was configured with
     */
    public String getSchemeId() {
        return schemeId;
    }

    /**
     * @see ConfigurableAuthenticationScheme#configure(String, Properties)
     */
    public void configure(String schemeId, Properties config) {
        this.schemeId = schemeId;
        this.config = config;
    }

    /**
     * @return the properties configured on this instance, or an empty Properties if none configured
     */
    public Properties getConfig() {
        if (config == null) {
            config = new Properties();
        }
        return config;
    }

    /**
     * Implementation of authenticate method that notifies UserLogin of successful or failed attempts
     * This method is not intended to be re-implemented
     * Subclasses should instead implement authenticate(AuthenticationCredentials, UserLogin)
     */
    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
        if (!(credentials instanceof AuthenticationCredentials)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        AuthenticationCredentials authenticationCredentials = (AuthenticationCredentials) credentials;
        String schemeId = authenticationCredentials.getAuthenticationScheme();
        UserLogin userLogin = UserLoginTracker.getLoginOnThread();
        Authenticated authenticated;
        try {
            authenticated = authenticate(authenticationCredentials, userLogin);
            userLogin.authenticationSuccessful(schemeId, authenticated);
        }
        catch (Exception e) {
            userLogin.authenticationFailed(schemeId);
            throw new ContextAuthenticationException(e.getMessage(), e);
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
