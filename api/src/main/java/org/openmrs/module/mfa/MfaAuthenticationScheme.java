/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordCredentials;
import org.springframework.stereotype.Component;

/**
 * An authentication scheme that supports multiple authentication factors
 */
@Component
public class MfaAuthenticationScheme extends DaoAuthenticationScheme {

	public MfaAuthenticationScheme() {
	}
	
	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {

		// Support situation where module has been installed, but either not configured, or explicitly disabled
		// In this case, fall back to standard OpenMRS authentication
		if (credentials instanceof UsernamePasswordCredentials) {
			MfaProperties mfaProperties = new MfaProperties();
			if (!mfaProperties.isMfaEnabled()) {
				return new UsernamePasswordAuthenticationScheme().authenticate(credentials);
			}
		}

		if (!(credentials instanceof MfaAuthenticationCredentials)) {
			throw new ContextAuthenticationException("The credentials provided are invalid.");
		}

		MfaAuthenticationCredentials mfaCredentials = (MfaAuthenticationCredentials) credentials;

		// Authenticate with primary authenticator
		Authenticator primaryAuthenticator = mfaCredentials.getPrimaryAuthenticator();
		AuthenticatorCredentials primaryCredentials = mfaCredentials.getPrimaryCredentials();
		if (primaryAuthenticator == null || primaryCredentials == null) {
			throw new ContextAuthenticationException("The credentials provided are invalid");
		}
		User primaryUser = primaryAuthenticator.authenticate(primaryCredentials);
		if (primaryUser == null) {
			throw new ContextAuthenticationException("The credentials provided are invalid");
		}

		// Authenticate with secondary authenticator
		Authenticator secondaryAuthenticator = mfaCredentials.getSecondaryAuthenticator();
		AuthenticatorCredentials secondaryCredentials = mfaCredentials.getSecondaryCredentials();
		if (secondaryAuthenticator != null) {
			if (secondaryCredentials == null) {
				throw new ContextAuthenticationException("The credentials provided are invalid");
			}
			User secondaryUser = secondaryAuthenticator.authenticate(secondaryCredentials);
			if (!primaryUser.equals(secondaryUser)) {
				throw new ContextAuthenticationException("The credentials provided are invalid");
			}
		}
		else {
			if (secondaryCredentials != null) {
				throw new ContextAuthenticationException("The credentials provided are invalid");
			}
		}

		// If the user's match, return a successful Authenticated user
		return new BasicAuthenticated(primaryUser, credentials.getAuthenticationScheme());
	}
}
