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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.AuthenticationUtil;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * An authentication scheme that supports a primary and secondary authentication factor
 */
public class TwoFactorAuthenticationScheme extends DaoAuthenticationScheme implements WebAuthenticationScheme {

	protected final Log log = LogFactory.getLog(getClass());

	// User property components
	public static final String AUTHENTICATION = "authentication";
	public static final String SECONDARY_TYPE = "secondaryType";
	private static final String DOT = ".";

	protected String schemeId;
	protected List<String> primaryOptions = new ArrayList<>();
	protected List<String> secondaryOptions = new ArrayList<>();

	public TwoFactorAuthenticationScheme() {
		this.schemeId = getClass().getName();
	}

	/**
	 * @return the configured schemeId
	 */
	@Override
	public String getSchemeId() {
		return schemeId;
	}

	/**
	 * This supports configuring the `primaryOptions` and `secondaryOptions` that are supported factors
	 * These are both expected to be comma-delimited lists of schemeIds
	 * @see ConfigurableAuthenticationScheme#configure(String, Properties)
	 */
	@Override
	public void configure(String schemeId, Properties config) {
		this.schemeId = schemeId;
		primaryOptions = AuthenticationUtil.getStringList(config.getProperty("primaryOptions"), ",");
		secondaryOptions = AuthenticationUtil.getStringList(config.getProperty("secondaryOptions"), ",");
	}

	@Override
	public String getChallengeUrl(AuthenticationSession session) {
		User candidateUser = session.getAuthenticationContext().getUser();
		if (candidateUser == null) {
			return getPrimaryAuthenticationScheme().getChallengeUrl(session);
		}
		WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(candidateUser);
		if (secondaryScheme != null) {
			return getSecondaryAuthenticationScheme(candidateUser).getChallengeUrl(session);
		}
		return null;
	}

	/**
	 * @see WebAuthenticationScheme#getCredentials(AuthenticationSession)
	 */
	@Override
	public AuthenticationCredentials getCredentials(AuthenticationSession session) {

		AuthenticationContext context = session.getAuthenticationContext();
		AuthenticationCredentials existingCredentials = context.getUnvalidatedCredentials(schemeId);
		if (existingCredentials != null) {
			return existingCredentials;
		}

		// Primary Authentication
		WebAuthenticationScheme primaryScheme = getPrimaryAuthenticationScheme();
		if (!context.isCredentialValidated(primaryScheme.getSchemeId())) {
			AuthenticationCredentials primaryCredentials = primaryScheme.getCredentials(session);
			if (primaryCredentials != null) {
				try {
					session.authenticate(primaryScheme, primaryCredentials);
				} catch (Exception e) {
					log.trace("Primary Authentication Failed: " + primaryCredentials.getClientName(), e);
				}
			}
		}

		// Secondary Authentication
		if (context.getUser() != null) {
			WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(context.getUser());
			if (secondaryScheme != null) {
				if (!context.isCredentialValidated(secondaryScheme.getSchemeId())) {
					AuthenticationCredentials secondaryCredentials = secondaryScheme.getCredentials(session);
					if (secondaryCredentials != null) {
						try {
							session.authenticate(secondaryScheme, secondaryCredentials).getUser();
						} catch (Exception e) {
							log.trace("Secondary Authentication Failed: " + secondaryCredentials.getClientName(), e);
						}
					}
				}
			}
			if (secondaryScheme == null || context.isCredentialValidated(secondaryScheme.getSchemeId())) {
				TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials(
						context.getUser(), context.getValidatedCredentials()
				);
				context.addUnvalidatedCredentials(credentials);
				return credentials;
			}

		}
		return null;
	}

	/**
	 * @see AuthenticationScheme#authenticate(Credentials)
	 */
	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
		// Ensure the credentials provided are of the expected type
		if (!(credentials instanceof TwoFactorAuthenticationCredentials)) {
			throw new ContextAuthenticationException("authentication.error.invalidCredentials");
		}
		TwoFactorAuthenticationCredentials mfaCreds = (TwoFactorAuthenticationCredentials) credentials;
		if (!mfaCreds.validatedCredentials.contains(getPrimaryAuthenticationScheme().getSchemeId())) {
			throw new ContextAuthenticationException("authentication.error.invalidCredentials");
		}
		WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(mfaCreds.user);
		if (secondaryScheme != null) {
			if (!mfaCreds.validatedCredentials.contains(secondaryScheme.getSchemeId())) {
				throw new ContextAuthenticationException("authentication.error.invalidCredentials");
			}
		}
		return new BasicAuthenticated(mfaCreds.user, credentials.getAuthenticationScheme());
	}

	/**
	 * This returns the WebAuthenticationScheme that is configured as the primary authentication scheme,
	 * defined as the first configured authentication scheme in the `primaryOptions` configuration property
	 * If no AuthenticationScheme can be returned, or if it is not a WebAuthenticationScheme, an exception is thrown
	 * @return the WebAuthenticationScheme to use for the given MultiFactorAuthenticationCredentials
	 */
	protected WebAuthenticationScheme getPrimaryAuthenticationScheme() {
		String authScheme = null;
		if (!primaryOptions.isEmpty()) {
			authScheme = primaryOptions.get(0);
		}
		if (authScheme == null) {
			throw new ContextAuthenticationException("No primary authentication scheme has been configured");
		}
		try {
			AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme(authScheme);
			if (scheme instanceof WebAuthenticationScheme) {
				return (WebAuthenticationScheme) scheme;
			}
			else {
				throw new ContextAuthenticationException("Primary scheme must be a WebAuthenticationScheme");
			}
		}
		catch (Exception e) {
			throw new ContextAuthenticationException("Error loading primary authentication scheme", e);
		}
	}

	/**
	 * This returns the WebAuthenticationScheme that is configured for the given User
	 * This is configured via a user property named `authentication.secondaryType`
	 * This throws an Exception the configured AuthenticationScheme is not a WebAuthenticationScheme
	 * @param user the User to check for configured secondary WebAuthenticationScheme
	 * @return the WebAuthenticationScheme to use for the given MultiFactorAuthenticationCredentials
	 */
	protected WebAuthenticationScheme getSecondaryAuthenticationScheme(User user) {
		if (user != null) {
			String secondaryName = user.getUserProperty(AUTHENTICATION + DOT + SECONDARY_TYPE);
			if (StringUtils.isNotBlank(secondaryName)) {
				AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme(secondaryName);
				if (scheme instanceof WebAuthenticationScheme) {
					return (WebAuthenticationScheme) scheme;
				}
				else {
					throw new ContextAuthenticationException("Secondary scheme must be a WebAuthenticationScheme");
				}
			}
		}
		return null;
	}

	/**
	 * @return the primary authentication scheme options configured
	 */
	public List<String> getPrimaryOptions() {
		return primaryOptions;
	}

	/**
	 * @return the secondary authentication scheme options configured
	 */
	public List<String> getSecondaryOptions() {
		return secondaryOptions;
	}

	/**
	 * Credentials inner class, to enable access and visibility of credential details to be limited to scheme
	 */
	public class TwoFactorAuthenticationCredentials implements AuthenticationCredentials {

		protected final User user;
		protected final Set<String> validatedCredentials = new HashSet<>();

		@Override
		public String getAuthenticationScheme() {
			return schemeId;
		}

		protected TwoFactorAuthenticationCredentials(User user, Set<String> validatedCredentials) {
			this.user = user;
			if (validatedCredentials != null) {
				this.validatedCredentials.addAll(validatedCredentials);
			}
		}

		@Override
		public String getClientName() {
			return user == null ? null : user.getUsername();
		}
	}
}
