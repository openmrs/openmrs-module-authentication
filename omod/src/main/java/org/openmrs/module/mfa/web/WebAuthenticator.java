/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.openmrs.module.mfa.Authenticator;
import org.openmrs.module.mfa.AuthenticatorCredentials;

/**
 * Represents a particular method of authentication.
 */
public interface WebAuthenticator extends Authenticator {

    /**
     * This method is intended to be used by implementations to inspect the AuthenticationSession for any
     * submitted credentials.  If found, this should construct and return valid AuthenticatorCredentials.
     * If not found, should return null.
     * @param session the current AuthenticationSession
     * @return Credentials that could be passed to the authenticate method to attempt authentication or null if none
     */
    AuthenticatorCredentials getCredentials(AuthenticationSession session);

    /**
     * This method is intended to be used by implementations to indicate the url for a user authentication challenge
     * @param session the current AuthenticationSession
     */
    String getChallengeUrl(AuthenticationSession session);
}
