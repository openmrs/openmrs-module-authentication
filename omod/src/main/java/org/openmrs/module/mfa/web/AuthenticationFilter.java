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
import org.openmrs.api.context.Context;
import org.openmrs.module.mfa.MfaConfiguration;
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
import java.util.List;

import static org.openmrs.module.mfa.MfaConfiguration.FILTER_ENABLED;
import static org.openmrs.module.mfa.MfaConfiguration.FILTER_UNAUTHENTICATED_URLS;

/**
 * This servlet filter checks whether the user is authenticated, and if not, redirects to the
 * configured login page controller. This filter is configurable via "mfa.properties" in the
 * application data directory, which include whether the filter is enabled or disabled, and what url patterns
 * do not require authentication:
 *
 * filter.enabled = true/false
 * filter.unauthenticatedUrls = comma-delimited list of url patterns that should not require authentication
 *
 * NOTE: If a pattern in unprotected urls starts with a "*", then
 * it is assumed to be an "ends with" pattern match, and will match on any path that ends with the
 * indicated pattern In order to load the login page and successfully login on a 1.x system using
 * legacyui, the following unprotectedUrls configuration can be used:
 * unprotectedUrls=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png
 */
public class AuthenticationFilter implements Filter {
	
	protected final Log log = LogFactory.getLog(getClass());

	private final MfaConfiguration configuration;
	private final AntPathMatcher matcher;
	
	public AuthenticationFilter() {
		matcher = new AntPathMatcher();
		// matcher.setCaseSensitive(false); This is only available in Spring versions included in 2.5.x+
		matcher.setTrimTokens(true);
		configuration = new MfaConfiguration();
	}
	
	@Override
	public void init(FilterConfig filterConfig) {
	}
	
	@Override
	public void destroy() {
	}
	
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
	        throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		
		if (!Context.isAuthenticated()) {

			if (configuration.getBoolean(FILTER_ENABLED, false)) {

				String moduleLoginUrl = "/module/login/login.htm";
				String moduleLogoutUrl = "/module/login/logout.htm";

				boolean requiresAuth = !(matchesPath(request, moduleLoginUrl) || matchesPath(request, moduleLogoutUrl));
				List<String> unprotectedUrls = configuration.getStringList(FILTER_UNAUTHENTICATED_URLS);
				for (String pattern : unprotectedUrls) {
					requiresAuth = requiresAuth && !matchesPath(request, pattern);
				}
				if (requiresAuth) {
					if (log.isDebugEnabled()) {
						log.debug("Requested Servlet path: " + request.getServletPath());
						log.debug("Requested Request URI: " + request.getRequestURI());
						log.debug("Authentication filter redirect to: " + moduleLoginUrl);
					}
					response.sendRedirect(request.getContextPath() + moduleLoginUrl);
					return;
				}

			}
		}
		
		chain.doFilter(servletRequest, servletResponse);
	}
	
	/**
	 * @return true if either the servletPath or requestUri of the given request matches the given
	 *         pattern
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
}
