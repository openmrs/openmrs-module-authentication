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

		Authenticated authenticated;

		try {
			// Support situation where module has been installed, but either not configured, or explicitly disabled
			// In this case, fall back to standard OpenMRS authentication
			if (credentials instanceof UsernamePasswordCredentials) {
				if (!MfaProperties.isMfaEnabled()) {
					authenticated = new UsernamePasswordAuthenticationScheme().authenticate(credentials);
				}
				else {
					throw new ContextAuthenticationException("The credentials provided are invalid.");
				}
			}
			else {
				if (!(credentials instanceof MfaAuthenticationCredentials)) {
					throw new ContextAuthenticationException("The credentials provided are invalid.");
				}

				MfaAuthenticationCredentials mfaCredentials = (MfaAuthenticationCredentials) credentials;

				// Authenticate with primary authenticator
				Authenticator primaryAuthenticator = mfaCredentials.getPrimaryAuthenticator();
				AuthenticatorCredentials primaryCredentials = mfaCredentials.getPrimaryCredentials();
				if (primaryAuthenticator == null || primaryCredentials == null) {
					throw new ContextAuthenticationException("Primary authentication has not been completed");
				}
				User primaryUser = primaryAuthenticator.authenticate(primaryCredentials);
				if (primaryUser == null) {
					throw new ContextAuthenticationException("Primary authentication failed");
				}
				else {
					MfaLogger.addUserToContext(primaryUser);
				}

				// Authenticate with secondary authenticator
				Authenticator secondaryAuthenticator = mfaCredentials.getSecondaryAuthenticator();
				AuthenticatorCredentials secondaryCredentials = mfaCredentials.getSecondaryCredentials();
				if (secondaryAuthenticator != null) {
					if (secondaryCredentials == null) {
						throw new ContextAuthenticationException("Secondary authentication has not been completed");
					}
					User secondaryUser = secondaryAuthenticator.authenticate(secondaryCredentials);
					try {
						if (secondaryUser == null) {
							throw new ContextAuthenticationException("Secondary authentication failed");
						}
						if (!primaryUser.equals(secondaryUser)) {
							throw new ContextAuthenticationException("Primary and secondary authentication do not match");
						}
						MfaLogger.addUserToContext(secondaryUser);
						MfaLogger.logAuthEvent(MfaLogger.Event.MFA_SECONDARY_AUTH_SUCCEEDED, secondaryCredentials);
					} catch (ContextAuthenticationException e) {
						MfaLogger.logAuthEvent(MfaLogger.Event.MFA_SECONDARY_AUTH_FAILED, secondaryCredentials);
						throw e;
					}
				} else {
					if (secondaryCredentials != null) {
						throw new ContextAuthenticationException("Secondary credentials provided without authenticator");
					}
				}

				// If the user's match, return a successful Authenticated user
				authenticated = new BasicAuthenticated(primaryUser, credentials.getAuthenticationScheme());
				MfaLogger.addUserToContext(authenticated.getUser());
			}
		}
		catch (ContextAuthenticationException e) {
			throw e;
		}

		return authenticated;
	}
}
