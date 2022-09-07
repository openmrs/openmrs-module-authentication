/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.module.mfa.AuthenticationContext;
import org.openmrs.module.mfa.Authenticator;
import org.openmrs.module.mfa.AuthenticatorCredentials;
import org.openmrs.module.mfa.MfaProperties;
import org.openmrs.module.mfa.MfaUser;
import org.springframework.util.AntPathMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This servlet filter checks whether the user is authenticated, and if not, redirects to the
 * configured login page controller. This filter is configurable via "mfa.properties" in the
 * application data directory, which include whether the filter is enabled or disabled, and what url patterns
 * do not require authentication:
 *
 * mfa.enabled = true/false
 * mfa.unauthenticatedUrls = comma-delimited list of url patterns that should not require authentication
 *
 * NOTE: If a pattern in unprotected urls starts with a "*", then
 * it is assumed to be an "ends with" pattern match, and will match on any path that ends with the
 * indicated pattern In order to load the login page and successfully login on a 1.x system using
 * legacyui, the following unprotectedUrls configuration can be used:
 * /login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png
 */
public class AuthenticationFilter implements Filter {
	
	protected final Log log = LogFactory.getLog(getClass());

	private AntPathMatcher matcher;
	
	public AuthenticationFilter() {
	}
	
	@Override
	public void init(FilterConfig filterConfig) {
		log.info("MFA Authentication Filter initializing");
		// Setup path matcher
		matcher = new AntPathMatcher();
		// matcher.setCaseSensitive(false); This is only available in Spring versions included in 2.5.x+
		matcher.setTrimTokens(true);
	}
	
	@Override
	public void destroy() {
		matcher = null;
	}
	
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
	        throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		
		if (!Context.isAuthenticated()) {

			AuthenticationSession session = new AuthenticationSession(request, response);
			AuthenticationContext context = session.getAuthenticationContext();
			MfaProperties config = context.getConfig();

			if (config.isMfaEnabled()) {

				boolean requiresAuth = true;
				for (String pattern : config.getUnauthenticatedUrlPatterns()) {
					requiresAuth = requiresAuth && !matchesPath(request, pattern);
				}
				if (requiresAuth) {
					if (log.isDebugEnabled()) {
						log.debug("Requested Servlet path: " + request.getServletPath());
						log.debug("Requested Request URI: " + request.getRequestURI());
					}

					// If no primary authentication has taken place, ensure the primary authenticator passes
					User candidateUser = null;
					if (!context.isPrimaryAuthenticationComplete()) {
						WebAuthenticator primaryAuthenticator = validate(context.getPrimaryAuthenticator());

						// Attempt to authenticate and if unable to do so, initiate challenge
						AuthenticatorCredentials credentials = primaryAuthenticator.getCredentials(session);
						if (credentials != null) {
							candidateUser = primaryAuthenticator.authenticate(credentials);
						}
						if (candidateUser == null) {
							primaryAuthenticator.challenge(session);
						}
						else {
							context.setPrimaryAuthenticationComplete(new MfaUser(candidateUser), credentials);
						}
					}

					// If here, this means that primary authentication was successful, and there is a candidate user
					// Check if this user has a secondary authentication configured
					// If they do, attempt to retrieve credentials, otherwise, redirect to challenge for them.

					if (context.isPrimaryAuthenticationComplete()) {
						WebAuthenticator secondaryAuthenticator = validate(context.getSecondaryAuthenticator());
						if (secondaryAuthenticator != null) {
							AuthenticatorCredentials credentials = secondaryAuthenticator.getCredentials(session);
							if (credentials == null) {
								secondaryAuthenticator.challenge(session);
							}
						}

						// If here, that means that primary authentication is complete and secondary authentication
						// is either not enabled for this user, or credentials have been retrieved.  Authenticate.

						Context.authenticate(context.getCredentials());

						// Once authenticated,  clear the authentication session
						session.reset();
					}
				}
			}
		}
		
		chain.doFilter(servletRequest, servletResponse);
	}
	
	/**
	 * @return true if either the servletPath or requestUri of the given request matches the given pattern
	 */
	protected boolean matchesPath(HttpServletRequest request, String pattern) {
		if (pattern.startsWith("*")) {
			pattern = "/**/" + pattern;
		}
		if (matcher.match(pattern, request.getServletPath())) {
			return true;
		}
		// We need to account for urls that are behind OpenMRS servlets and serving various resources
		// For example, the moduleServlet will show a servlet path of "/ms",
		// module resources will show "/moduleResources",
		return matcher.match(request.getContextPath() + pattern, request.getRequestURI());
	}

	/**
	 * Validates that the given Authenticator is a WebAuthenticator, throwing an Exception if not
	 * @return the passed Authenticator cast to a WebAuthenticator
	 */
	protected WebAuthenticator validate(Authenticator authenticator) {
		WebAuthenticator ret = null;
		if (authenticator != null) {
			if (authenticator instanceof WebAuthenticator) {
				ret = (WebAuthenticator) authenticator;
			}
			else {
				throw new UnsupportedOperationException("Only WebAuthenticators are currently supported");
			}
		}
		return ret;
	}
}
