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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.util.OpenmrsConstants;

/**
 * This filter checks if an authenticated user has been flagged by the admin to
 * change his password on first/subsequent login.
 */
public class ForcePasswordChangeFilter implements Filter {
	
	private FilterConfig config;

	private boolean supportForcedPasswordChange;

	String changePasswordUrl;


	protected final Log log = LogFactory.getLog(getClass());

	@Override
	public void init(FilterConfig config) throws ServletException {
		this.config = config;
		this.changePasswordUrl = AuthenticationConfig.getChangePasswordUrl();
		this.supportForcedPasswordChange = AuthenticationConfig.getBoolean(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, false);
	}


	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (!supportForcedPasswordChange || WebUtil.isWhiteListed(request, AuthenticationConfig.getPasswordChangeWhiteList())) {
			chain.doFilter(request, response);
			return;
		}

		AuthenticationSession session = getAuthenticationSession(request, response);
		UserLogin userLogin = session.getUserLogin();
		String changePasswordProperty = userLogin.getUser().
		  getUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD);
		Boolean changePasswordFlag = BooleanUtils.isTrue(Boolean.valueOf(changePasswordProperty));
		if (userLogin.isUserAuthenticated() && BooleanUtils.isTrue(changePasswordFlag)) {
			if (changePasswordUrl != null) {
				request.getRequestDispatcher(changePasswordUrl).forward(request, response);
			} else {
				log.error("Change password URL is not set. Continuing with the request chain.");
				chain.doFilter(request, response);
			}
		} else {
			chain.doFilter(request, response);
		}
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
