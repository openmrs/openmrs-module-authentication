/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.Authenticator;
import org.openmrs.module.authentication.AuthenticatorCredentials;
import org.openmrs.module.authentication.CandidateUser;
import org.openmrs.web.WebConstants;
import org.springframework.util.AntPathMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * This servlet filter checks whether the user is authenticated, and if not, redirects to the
 * configured login page controller. This filter is configurable via runtime properties,
 * which include whether the filter is enabled or disabled, and what url patterns do not require authentication:
 *
 * authentication.filter.enabled = true/false
 * authentication.filter.skipPatterns = comma-delimited list of url patterns that should not require authentication
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
		log.info("Authentication Filter initializing");
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

		AuthenticationSession session = new AuthenticationSession(request, response);
		AuthenticationContext context = session.getAuthenticationContext();

		try {
			AuthenticationLogger.addToContext(AuthenticationLogger.SESSION_ID, request.getSession().getId());
			AuthenticationLogger.addToContext(AuthenticationLogger.IP_ADDRESS, request.getRemoteAddr());
			AuthenticationLogger.addUserToContext(Context.getAuthenticatedUser());

			if (!Context.isAuthenticated()) {

				if (!AuthenticationConfig.isConfigurationCached()) {
					AuthenticationConfig.reloadConfigFromRuntimeProperties(WebConstants.WEBAPP_NAME);
				}

				if (AuthenticationConfig.isFilterEnabled()) {

					boolean requiresAuth = !isSkipPattern(request);
					if (requiresAuth) {
						if (log.isDebugEnabled()) {
							log.debug("Requested Servlet path: " + request.getServletPath());
							log.debug("Requested Request URI: " + request.getRequestURI());
						}

						// If no primary authentication has taken place, ensure the primary authenticator passes
						User candidateUser = null;
						// TODO: Currently we always use the default primary authenticator.
						// TODO: If we want to allow users to choose their primary authenticator, would need to change this
						WebAuthenticator primaryAuthenticator = validate(context.getDefaultPrimaryAuthenticator());
						if (!context.isPrimaryAuthenticationComplete()) {
							// Attempt to authenticate and if unable to do so, initiate challenge
							AuthenticatorCredentials credentials = primaryAuthenticator.getCredentials(session);
							if (credentials != null) {
								candidateUser = primaryAuthenticator.authenticate(credentials);
								if (candidateUser != null) {
									AuthenticationLogger.addUserToContext(candidateUser);
									AuthenticationLogger.logAuthEvent(AuthenticationLogger.Event.AUTHENTICATION_PRIMARY_AUTH_SUCCEEDED, credentials);
								} else {
									AuthenticationLogger.logAuthEvent(AuthenticationLogger.Event.AUTHENTICATION_PRIMARY_AUTH_FAILED, credentials);
								}
							}
							if (candidateUser == null) {
								response.sendRedirect(primaryAuthenticator.getChallengeUrl(session));
							} else {
								context.setPrimaryAuthenticationComplete(new CandidateUser(candidateUser), credentials);
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
									response.sendRedirect(secondaryAuthenticator.getChallengeUrl(session));
								} else {
									context.getCredentials().setSecondaryCredentials(credentials);
								}
							}

							// If here, that means that primary authentication is complete and secondary authentication
							// is either not enabled for this user, or credentials have been retrieved.  Authenticate.
							if (context.isReadyToAuthenticate()) {
								try {
									Context.authenticate(context.getCredentials());

									// If Authentication is successful, we regenerate session
									regenerateSession(request);

									// Redirect to appropriate success url
									response.sendRedirect(determineSuccessRedirectUrl(request));
								}
								catch (ContextAuthenticationException e) {
									String challengeUrl = primaryAuthenticator.getChallengeUrl(session);
									if (secondaryAuthenticator != null) {
										challengeUrl = secondaryAuthenticator.getChallengeUrl(session);
									}
									// TODO: Add message as request or session attribute here??
									response.sendRedirect(challengeUrl);
								}
							}
						}
					}
				}
			} else {
			// If authenticated, reset the authentication session
				session.removeAuthenticationContext();
			}

			if (!response.isCommitted()) {
				chain.doFilter(servletRequest, servletResponse);
			}
		}
		finally {
			AuthenticationLogger.clearContext();
		}
	}

	protected boolean isSkipPattern(HttpServletRequest request) {
		for (String pattern : AuthenticationConfig.getFilterSkipPatterns()) {
			if (matchesPath(request, pattern)) {
				return true;
			}
		}
		return false;
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

	/**
	 * This regenerates the session associated with a request, by invalidating existing session, and creating a new
	 * session that contains the same attributes as the existing session.
	 * See:  <a href="https://stackoverflow.com/questions/8162646/how-to-refresh-jsessionid-cookie-after-login">SO</a>
	 * See:  <a href="https://owasp.org/www-community/attacks/Session_fixation">Session Fixation</a>
	 * @param request the request containing the session to regenerate
	 */
	protected HttpSession regenerateSession(HttpServletRequest request) {
		Properties sessionAttributes = new Properties();
		HttpSession existingSession = request.getSession(false);
		if (existingSession != null) {
			Enumeration<?> attrNames = existingSession.getAttributeNames();
			if (attrNames != null) {
				while (attrNames.hasMoreElements()) {
					String attribute = (String) attrNames.nextElement();
					sessionAttributes.put(attribute, existingSession.getAttribute(attribute));
				}
			}
			existingSession.invalidate();
		}
		HttpSession newSession = request.getSession(true);
		Enumeration<Object> attrNames = sessionAttributes.keys();
		if (attrNames != null) {
			while (attrNames.hasMoreElements()) {
				String attribute = (String) attrNames.nextElement();
				newSession.setAttribute(attribute, sessionAttributes.get(attribute));
			}
		}
		return newSession;
	}

	private String determineSuccessRedirectUrl(HttpServletRequest request) {
		// First check for any "redirect" or "refererURL" parameters in the request, default to context path
		String redirect = request.getParameter("redirect");
		if (StringUtils.isNotBlank(redirect)) {
			redirect = request.getParameter("refererURL");
		}
		if (StringUtils.isBlank(redirect)) {
			redirect = "/";
		}

		// If the redirect is not absolute URL, add the context path
		if (redirect.startsWith("/")) {
			redirect = request.getContextPath() + redirect;
		}
		// If the redirect is outside the context path, use the home page
		else if (!redirect.startsWith(request.getContextPath())) {
			redirect = request.getContextPath();
		}

		log.debug("Going to use redirect: '" + redirect + "'");

		return redirect;
	}
}
