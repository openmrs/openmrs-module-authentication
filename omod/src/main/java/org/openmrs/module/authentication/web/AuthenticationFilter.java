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
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.AuthenticationLogger;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.scheme.DelegatingAuthenticationScheme;
import org.openmrs.module.authentication.web.scheme.WebAuthenticationScheme;
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
import java.io.IOException;

/**
 * This servlet filter checks whether the user is authenticated, and if not, redirects to the configured login page.
 * This filter is configurable via runtime properties:
 * <p>
 * authentication.scheme = schemeId
 * authentication.whiteList = comma-delimited list of url patterns that should not require authentication
 * <p>
 * If `authentication.scheme` references a `WebAuthenticationScheme`, then this filter will activate.
 * If this is not configured, or does not implement `WebAuthenticationScheme`, no filtering will occur
 * <p>
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

	/**
	 * This module is intended to be fully configurable by implementations and not configured statically here
	 * @see Filter#init(FilterConfig)
	 */
	@Override
	public void init(FilterConfig filterConfig) {
		log.info("Authentication Filter initializing");
		matcher = new AntPathMatcher();
		matcher.setCaseSensitive(false);
		matcher.setTrimTokens(true);
	}

	/**
	 * @see Filter#destroy()
	 */
	@Override
	public void destroy() {
		matcher = null;
	}

	/**
	 * This filter operates on a specific type of AuthenticationScheme, which is a WebAuthenticationScheme
	 * If the configured scheme (authentication.scheme in the runtime properties) is a WebAuthenticationScheme, and
	 * if the user is not yet authenticated, then this filter will interact with the WebAuthenticationScheme to:
	 * <ul>
	 *     <li>Try to instantiate valid AuthenticationCredentials from the current request</li>
	 *     <li>Determine if there is a challenge URL where the user should be redirected to submit credentials</li>
	 *     <li>If credentials are incomplete, and a challenge URL is needed, redirect the user</li>
	 *     <li>Otherwise, if credentials are complete and no further challenge urls are presented, authenticate</li>
	 *     <li>Redirect back to a challenge URL if authentication fails</li>
	 *     <li>Redirect to an appropriate success URL if authentication succeeds</li>
	 * </ul>
	 * In order to allow challengeUrl redirection to work, this filter also checks a list of white-listed URL
	 * patterns to determine if a given URL should result in an authentication redirect or not.
	 * This is configurable in OpenMRS runtime properties as `authentication.whiteList`
	 * Typically this should be set to include any page and any resource (images, scripts, etc) that is needed for
	 * the challenge urls that the WebAuthenticationScheme instances will redirect to.
	 * <p>
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
	        throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		AuthenticationSession session = getAuthenticationSession(request, response);

		try {
			if (!session.isUserAuthenticated()) {

				if (!AuthenticationConfig.isConfigurationCacheEnabled()) {
					AuthenticationConfig.reloadConfigFromRuntimeProperties(WebConstants.WEBAPP_NAME);
				}

				AuthenticationContext authenticationContext = session.getAuthenticationContext();
				AuthenticationScheme authenticationScheme = getAuthenticationScheme();

				if (authenticationScheme instanceof WebAuthenticationScheme) {
					WebAuthenticationScheme webAuthenticationScheme = (WebAuthenticationScheme) authenticationScheme;
					if (!isWhiteListed(request)) {
						log.debug("Authentication required for " + request.getRequestURI());
						session.removeErrorMessage();

						// If any credentials were passed in the request or session, update the Context and return them
						AuthenticationCredentials credentials = webAuthenticationScheme.getCredentials(session);
						if (credentials != null) {
							try {
								authenticationContext.authenticate(credentials);
								session.regenerateHttpSession();  // Guard against session fixation attacks
								session.refreshDefaultLocale(); // Refresh context locale after authentication
								response.sendRedirect(determineSuccessRedirectUrl(request));
								return;
							}
							// If authentication fails, remove credentials and redirect back to re-initiate auth
							catch (Exception e) {
								session.setErrorMessage(e.getMessage());
								session.getAuthenticationContext().removeCredentials(credentials);
								response.sendRedirect(request.getRequestURI());
								return;
							}
						}
					}
				}
			}
			else {
				session.removeAuthenticationContext();  // If authenticated, remove authentication details from session
			}

			chain.doFilter(servletRequest, servletResponse);
		}
		finally {
			AuthenticationLogger.clearContext();
		}
	}

	/**
	 * @param request the HttpServletRequest to check
	 * @return true if the request is for a URL that matches a configured `authentication.whiteList` pattern
	 * @see AuthenticationFilter#matchesPath(HttpServletRequest, String)
	 */
	protected boolean isWhiteListed(HttpServletRequest request) {
		if (request.getMethod().equalsIgnoreCase("GET")) {
			for (String pattern : AuthenticationConfig.getWhiteList()) {
				if (matchesPath(request, pattern)) {
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * This checks the request servlet path, and the request requestURI against the given pattern
	 * The requestURI that is checked should be relative to the context path.
	 * So, if OpenMRS is deployed as a web application named "openmrs" at protocol://server:port/openmrs, a pattern
	 * of `/index.htm` would match a path at protocol://server:port/openmrs/index.htm
	 * This uses the ANT pattern matching syntax, with an additional feature that if a pattern starts with a "*",
	 * then it is assumed to be an "ends with" pattern match, and will match on any path that ends with the
	 * indicated pattern.  So, instead of passing in `/**\/*.jpg`, one can instead pass in simply `*.jpg`
	 */
	protected boolean matchesPath(HttpServletRequest request, String pattern) {
		if (pattern.startsWith("*")) {
			pattern = "/**/" + pattern;
		}
		if (matcher.match(pattern, request.getServletPath())) {
			return true;
		}
		return matcher.match(contextualizeUrl(request, pattern), request.getRequestURI());
	}

	/**
	 * Returns the configured authentication scheme.
	 * If this is a DelegatingAuthenticationScheme, returns the AuthenticationScheme that this delegates to
	 */
	protected AuthenticationScheme getAuthenticationScheme() {
		AuthenticationScheme authenticationScheme = Context.getAuthenticationScheme();
		if (authenticationScheme instanceof DelegatingAuthenticationScheme) {
			DelegatingAuthenticationScheme delegatingScheme = (DelegatingAuthenticationScheme) authenticationScheme;
			return delegatingScheme.getDelegatedAuthenticationScheme();
		}
		return authenticationScheme;
	}

	/**
	 * This returns an appropriate redirect URL following successful authentication
	 * This first checks for a parameter named `redirect`, followed by a parameter named `refererURL`, and then
	 * for the original request URI if this was a GET request.  If nothing found, sets to "/".
	 * This then ensures the url is within the OpenMRS context path.
	 * @param request the request to use to determine url redirection
	 */
	protected String determineSuccessRedirectUrl(HttpServletRequest request) {
		// First check for any "redirect" or "refererURL" parameters in the request, default to context path
		String redirect = request.getParameter("redirect");
		if (StringUtils.isBlank(redirect)) {
			redirect = request.getParameter("refererURL");
		}
		if (StringUtils.isBlank(redirect) && "GET".equals(request.getMethod())) {
			redirect = request.getRequestURI();
		}
		if (StringUtils.isBlank(redirect)) {
			redirect = "/";
		}
		redirect = contextualizeUrl(request, redirect);
		log.debug("Redirecting to: '" + redirect + "'");
		return redirect;
	}

	/**
	 * Appends the OpenMRS context path to the given URL if necessary
	 * @param request the request containing the context path
	 * @param url the url to contextualize
	 * @return the url, prepended with the context path if necessary
	 */
	protected String contextualizeUrl(HttpServletRequest request, String url) {
		if (!url.startsWith(request.getContextPath())) {
			url = request.getContextPath() + (url.startsWith("/") ? "" : "/") + url;
		}
		return url;
	}

	/**
	 * Return a valid AuthenticationSession for the given request
	 * @param request the HttpServletRequest to use to retrieve the AuthenticationSession
	 * @return the AuthenticationSession associated with this HttpServletRequest
	 */
	protected AuthenticationSession getAuthenticationSession(HttpServletRequest request, HttpServletResponse response) {
		return new AuthenticationSession(request, response);
	}
}
