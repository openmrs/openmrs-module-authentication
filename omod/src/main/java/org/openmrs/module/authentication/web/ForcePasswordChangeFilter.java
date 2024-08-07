package org.openmrs.module.authentication.web;

import java.io.IOException;
import java.util.List;

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

	private List<String> whiteList;

	String changePasswordUrl;


	protected final Log log = LogFactory.getLog(getClass());

	@Override
	public void init(FilterConfig config) throws ServletException {
		this.config = config;
		this.changePasswordUrl = AuthenticationConfig.getChangePasswordUrl();
		this.whiteList = AuthenticationConfig.getPasswordChangeWhiteList();
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

		if (!supportForcedPasswordChange || changePasswordUrl == null || WebUtil.isWhiteListed(request, whiteList)) {
			if (changePasswordUrl == null) {
				log.error("Change password URL is not set. Continuing with the request chain.");
			}
			chain.doFilter(request, response);
			return;
		}

		AuthenticationSession session = getAuthenticationSession(request, response);
		UserLogin userLogin = session.getUserLogin();
		String changePasswordProperty = userLogin.getUser().
		  getUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD);
		boolean changePasswordFlag = Boolean.parseBoolean(changePasswordProperty);
		if (userLogin.isUserAuthenticated() && changePasswordFlag) {
			request.getRequestDispatcher(changePasswordUrl).forward(request, response);
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
