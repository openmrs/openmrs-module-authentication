/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.credentials;

import org.openmrs.api.context.Credentials;

/**
 * Represents the credentials collected during the authentication session
 */
public class TwoFactorAuthenticationCredentials extends AuthenticationCredentials {

    private AuthenticationCredentials primaryCredentials;
    private AuthenticationCredentials secondaryCredentials;

    /**
     * Instantiates a new set of credentials with the given schemeId that identifies the linked AuthenticationScheme
     * @param schemeId the schemeId that identifies the particular AuthenticationScheme these are associated with
     */
    public TwoFactorAuthenticationCredentials(String schemeId) {
        super(schemeId);
    }

    /**
     * @see Credentials#getClientName()
     */
    @Override
    public String getClientName() {
        return (primaryCredentials != null ? primaryCredentials.getClientName() : null);
    }

    /**
     * @return the AuthenticationCredentials associated with the primary authentication scheme
     */
    public AuthenticationCredentials getPrimaryCredentials() {
        return primaryCredentials;
    }

    /**
     * @param primaryCredentials the AuthenticationCredentials associated with the primary authentication scheme
     */
    public void setPrimaryCredentials(AuthenticationCredentials primaryCredentials) {
        this.primaryCredentials = primaryCredentials;
    }

    /**
     * @return the AuthenticationCredentials associated with the secondary authentication scheme
     */
    public AuthenticationCredentials getSecondaryCredentials() {
        return secondaryCredentials;
    }

    /**
     * @param secondaryCredentials the AuthenticationCredentials associated with the secondary authentication scheme
     */
    public void setSecondaryCredentials(AuthenticationCredentials secondaryCredentials) {
        this.secondaryCredentials = secondaryCredentials;
    }
}
