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

import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.web.AuthenticationSession;

/**
 * Represents a particular method of authentication.
 */
public interface WebAuthenticationScheme extends ConfigurableAuthenticationScheme {

    /**
     * This method should return the challenge url at which a user could submit credentials
     * @param session the current AuthenticationSession
     */
    String getChallengeUrl(AuthenticationSession session);

    /**
     * This method is intended to be used by implementations to inspect the AuthenticationSession and
     * associated session and response for any submitted credentials.  If found, this should construct and
     * return valid AuthenticatorCredentials.  If not found, this should return null.
     * @param session the current AuthenticationSession
     * @return Credentials that could be passed to the authenticate method to attempt authentication or null if none
     */
    AuthenticationCredentials getCredentials(AuthenticationSession session);

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute prior to each authentication attempt
     */
    default void beforeAuthentication(AuthenticationSession session) {
    }

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute following a successful authentication
     */
    default void afterAuthenticationSuccess(AuthenticationSession session) {
    }

    /**
     * A WebAuthenticationScheme has hooks that allow for adding additional functionality within the authentication
     * workflow as desired.  This method will execute following a failed authentication
     */
    default void afterAuthenticationFailure(AuthenticationSession session) {
    }
}
