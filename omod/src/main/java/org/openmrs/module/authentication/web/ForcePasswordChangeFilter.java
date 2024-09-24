package org.openmrs.module.authentication.web;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.util.OpenmrsConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * This filter checks if an authenticated user has been flagged by the admin to
 * change his password on first/subsequent login.
 */
public class ForcePasswordChangeFilter extends OncePerRequestFilter {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	private boolean supportForcedPasswordChange;

	private boolean supportForcedPasswordChangeRestApi;

	private List<String> whiteList;

	private String changePasswordUrl;

	@Override
	public void initFilterBean() {
		FilterConfig filterConfig = getFilterConfig();
		if (filterConfig != null) {
			this.changePasswordUrl = WebUtil.contextualizeUrl(getFilterConfig().getServletContext().getContextPath(), AuthenticationConfig.getChangePasswordUrl());
		} else {
			this.changePasswordUrl = AuthenticationConfig.getChangePasswordUrl();
		}

		this.whiteList = AuthenticationConfig.getPasswordChangeWhiteList();
		this.supportForcedPasswordChange = AuthenticationConfig.getBoolean(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, false);
		this.supportForcedPasswordChangeRestApi = AuthenticationConfig.getBoolean(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE_REST_API, supportForcedPasswordChange);

		if (supportForcedPasswordChange && (changePasswordUrl == null || changePasswordUrl.isEmpty())) {
			log.error("Attempted to enable forced password changes, but no password change URL was set, so this feature is disabled.");
			this.supportForcedPasswordChange = false;
		}
	}

	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!response.isCommitted() && supportForcedPasswordChange && !WebUtil.isWhiteListed(request, whiteList)) {
			if (Context.isAuthenticated()) {
				User user = Context.getAuthenticatedUser();
				String changePasswordProperty = user.getUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD);

				if (Boolean.parseBoolean(changePasswordProperty)) {
					chain.doFilter(request, response);
					if (!response.isCommitted()) {
						sendRedirect(request, response);
					}
					return;
				}
			} else {
				// user is not logged in, but not yet on a whitelisted page
				sendRedirect(request, response);
			}
		}

		chain.doFilter(request, response);
	}


	/**
	 * Return a valid AuthenticationSession for the given request
	 * 
	 * @param request the HttpServletRequest to use to retrieve the
	 *                AuthenticationSession
	 * @return the AuthenticationSession associated with this HttpServletRequest
	 */
	protected AuthenticationSession getAuthenticationSession(HttpServletRequest request, HttpServletResponse response) {
		return new AuthenticationSession(request, response);
	}

	protected void sendRedirect(HttpServletRequest request, HttpServletResponse response) {
		// now, at this point, we need to know what kind of response to send
		List<MediaType> requestedMediaTypes = MediaType.parseMediaTypes(request.getHeader(HttpHeaders.ACCEPT));

		MediaType acceptType;
		if (requestedMediaTypes.isEmpty()) {
			acceptType = MediaType.ALL;
		} else {
			acceptType = requestedMediaTypes.get(0);
		}

		// here we try to detect "API requests"
		// API requests either:
		// 1. Start with /ws
		// 2. The client sends an Accept header indicating that it wants either a JSON or XML response as the first type
		//    (this latter because browsers do ask for JSON or XML, but much further down in the list of MIME-Types)
		if (this.supportForcedPasswordChangeRestApi &&
				request.getRequestURI().startsWith(request.getContextPath() + "/ws") ||
				(!acceptType.isWildcardType() && (
					MediaType.APPLICATION_JSON.isCompatibleWith(acceptType) ||
							MediaType.APPLICATION_XML.isCompatibleWith(acceptType) ||
							MediaType.TEXT_XML.isCompatibleWith(acceptType)))) {
			// assume a REST API, where we send a 403 with a Location header
			response.addHeader(HttpHeaders.LOCATION, WebUtil.contextualizeAbsoluteUrl(request, changePasswordUrl));
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		} else {
			// assume we're in a browser, send a redirect
			try {
				response.sendRedirect(WebUtil.contextualizeAbsoluteUrl(request, changePasswordUrl));
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
}
