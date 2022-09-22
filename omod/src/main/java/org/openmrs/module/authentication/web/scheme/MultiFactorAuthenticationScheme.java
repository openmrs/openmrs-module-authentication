/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.scheme;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Marker;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.web.AuthenticationSession;
import org.openmrs.module.authentication.web.credentials.MultiFactorAuthenticationCredentials;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.openmrs.module.authentication.AuthenticationLogger.getMarker;
import static org.openmrs.module.authentication.AuthenticationLogger.logEvent;

/**
 * An authentication scheme that supports a primary and secondary authentication factors
 */
public class MultiFactorAuthenticationScheme extends DaoAuthenticationScheme implements WebAuthenticationScheme {

	public static final Marker PRIMARY_SUCCEEDED = getMarker("PRIMARY_AUTHENTICATION_SUCCEEDED");
	public static final Marker PRIMARY_FAILED = getMarker("PRIMARY_AUTHENTICATION_FAILED");
	public static final Marker SECONDARY_SUCCEEDED = getMarker("SECONDARY_AUTHENTICATION_SUCCEEDED");
	public static final Marker SECONDARY_FAILED = getMarker("SECONDARY_AUTHENTICATION_FAILED");

	// User property components
	public static final String AUTHENTICATION = "authentication";
	public static final String SECONDARY_TYPE = "secondaryType";
	public static final String CONFIG = "config";
	private static final String DOT = ".";

	private String schemeId;
	private List<String> primaryOptions = new ArrayList<>();
	private List<String> secondaryOptions = new ArrayList<>();

	public MultiFactorAuthenticationScheme() {
		this.schemeId = getClass().getName();
	}

	@Override
	public String getSchemeId() {
		return schemeId;
	}

	@Override
	public void configure(String schemeId, Properties config) {
		this.schemeId = schemeId;
		primaryOptions = parseOptions(config.getProperty("primaryOptions"));
		secondaryOptions = parseOptions(config.getProperty("secondaryOptions"));
	}

	@Override
	public AuthenticationCredentials getCredentials(AuthenticationSession session) {
		AuthenticationContext context = session.getAuthenticationContext();
		MultiFactorAuthenticationCredentials credentials = getCredentialsFromContext(context);
		WebAuthenticationScheme primaryScheme = getPrimaryAuthenticationScheme(credentials);
		if (credentials.getPrimaryCredentials() == null) {
			credentials.setPrimaryCredentials(primaryScheme.getCredentials(session));
			credentials.setSecondaryCredentials(null);
		}
		if (credentials.getPrimaryCredentials() != null) {
			try {
				User candidateUser = primaryScheme.authenticate(credentials.getPrimaryCredentials()).getUser();
				AuthenticationLogger.addUserToContext(candidateUser);
				if (context.getCandidateUser() == null) {
					context.setCandidateUser(candidateUser);
					logEvent(PRIMARY_SUCCEEDED, credentials.getPrimaryCredentials().toString());
				}
				else if (!context.getCandidateUser().equals(candidateUser)) {
					throw new ContextAuthenticationException("Primary authentication returned conflicting user");
				}
				if (credentials.getSecondaryCredentials() == null) {
					WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(candidateUser);
					if (secondaryScheme != null) {
						credentials.setSecondaryCredentials(secondaryScheme.getCredentials(session));
					}
				}
			}
			catch (ContextAuthenticationException e) {
				logEvent(PRIMARY_FAILED, credentials.getPrimaryCredentials().toString());
				context.removeCredentials(credentials.getPrimaryCredentials());
				credentials.setPrimaryCredentials(null);
				context.setCandidateUser(null);
			}
		}

		return credentials;
	}

	@Override
	public String getChallengeUrl(AuthenticationSession session) {
		AuthenticationContext context = session.getAuthenticationContext();
		MultiFactorAuthenticationCredentials credentials = getCredentialsFromContext(context);
		if (credentials.getPrimaryCredentials() == null) {
			WebAuthenticationScheme primaryScheme = getPrimaryAuthenticationScheme(credentials);
			context.removeCredentials(primaryScheme.getSchemeId());
			return primaryScheme.getChallengeUrl(session);
		}
		else if (credentials.getSecondaryCredentials() == null) {
			WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(context.getCandidateUser());
			if (secondaryScheme != null) {
				context.removeCredentials(secondaryScheme.getSchemeId());
				return secondaryScheme.getChallengeUrl(session);
			}
		}
		return null;
	}

	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {

		// Ensure the credentials provided are of the expected type
		if (!(credentials instanceof MultiFactorAuthenticationCredentials)) {
			throw new ContextAuthenticationException("The credentials provided are invalid.");
		}

		MultiFactorAuthenticationCredentials mfaCreds = (MultiFactorAuthenticationCredentials) credentials;

		Authenticated authenticated = null;
		Authenticated secondaryAuthenticated = null;

		// Authenticate with primary authenticator
		AuthenticationScheme primaryScheme = getPrimaryAuthenticationScheme(mfaCreds);
		AuthenticationCredentials primaryCredentials = mfaCreds.getPrimaryCredentials();
		if (primaryCredentials == null) {
			throw new ContextAuthenticationException("Primary authentication has not been completed");
		}
		try {
			authenticated = primaryScheme.authenticate(primaryCredentials);
		}
		catch (ContextAuthenticationException e) {
			mfaCreds.setPrimaryCredentials(null);
			mfaCreds.setSecondaryCredentials(null);
			throw e;
		}
		AuthenticationLogger.addUserToContext(authenticated.getUser());

		// Authenticate with secondary authenticator
		AuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(authenticated.getUser());
		AuthenticationCredentials secondaryCredentials = mfaCreds.getSecondaryCredentials();
		if (secondaryScheme != null) {
			if (secondaryCredentials == null) {
				throw new ContextAuthenticationException("Secondary authentication has not been completed");
			}
			try {
				secondaryAuthenticated = secondaryScheme.authenticate(secondaryCredentials);
				if (!authenticated.getUser().equals(secondaryAuthenticated.getUser())) {
					throw new ContextAuthenticationException("Primary and secondary authentication do not match");
				}
				logEvent(SECONDARY_SUCCEEDED, secondaryCredentials.toString());
			}
			catch (ContextAuthenticationException e) {
				logEvent(SECONDARY_FAILED, secondaryCredentials.toString());
				mfaCreds.setSecondaryCredentials(null);
				throw new ContextAuthenticationException("Secondary authentication failed");
			}
		}

		return authenticated;
	}

	protected WebAuthenticationScheme getPrimaryAuthenticationScheme(MultiFactorAuthenticationCredentials credentials) {
		AuthenticationCredentials primaryCredentials = credentials.getPrimaryCredentials();
		String authScheme = null;
		if (primaryCredentials != null) {
			authScheme = primaryCredentials.getAuthenticationScheme();
		}
		if (authScheme == null && !primaryOptions.isEmpty()) {
			authScheme = primaryOptions.get(0);
		}
		if (authScheme == null) {
			throw new ContextAuthenticationException("No primary authentication scheme has been configured");
		}
		try {
			AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme(primaryOptions.get(0));
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

	protected MultiFactorAuthenticationCredentials getCredentialsFromContext(AuthenticationContext context) {
		MultiFactorAuthenticationCredentials creds = (MultiFactorAuthenticationCredentials) context.getCredentials(schemeId);
		if (creds == null) {
			creds = new MultiFactorAuthenticationCredentials(schemeId);
			context.addCredentials(creds);
		}
		return creds;
	}

	protected List<String> parseOptions(String optionString) {
		List<String> options = new ArrayList<>();
		if (StringUtils.isNotBlank(optionString)) {
			options.addAll(Arrays.asList(optionString.split(",")));
		}
		return options;
	}
}
