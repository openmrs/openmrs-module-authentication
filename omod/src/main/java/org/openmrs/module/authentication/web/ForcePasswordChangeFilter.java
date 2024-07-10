package org.openmrs.module.authentication.web;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.BooleanUtils;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.util.OpenmrsConstants;

/**
 * This filter checks if an authenticated user has been flagged by the admin to
 * change his password on first/subsequent login.
 */
public class ForcePasswordChangeFilter implements Filter {
	private FilterConfig config;

	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
	}

	/**
	 * @see javax.servlet.Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (WebUtil.isWhiteListed(request, AuthenticationConfig.getPasswordChangeWhiteList())) {
			chain.doFilter(request, response);
			return;
		}
		AuthenticationSession session = getAuthenticationSession(request, response);
		UserLogin userLogin = session.getUserLogin();
		String changePasswordProperty = userLogin.getUser().getUserProperties()
				.get(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD);
		Boolean changePasswordFlag = AuthenticationConfig.getBoolean(changePasswordProperty, false);

		if (userLogin.isUserAuthenticated() &&
				BooleanUtils.isTrue(changePasswordFlag)) {
			config.getServletContext().getRequestDispatcher(AuthenticationConfig.getChangePasswordUrl())
					.forward(request, response);
		} else {
			chain.doFilter(request, response);
		}
	}

	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {
		this.config = config;
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

}