package org.openmrs.module.authentication.web;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.util.OpenmrsConstants;

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

/**
 * This filter checks if an authenticated user has been flagged to change his password on first/subsequent login.
 * If so, and a password change url has been configured, this redirects the user to that page.
 */
public class ForcePasswordChangeFilter implements Filter {

	private boolean supportForcedPasswordChange;
	private List<String> whiteList;
	String changePasswordUrl;

	private final Log log = LogFactory.getLog(getClass());

	@Override
	public void init(FilterConfig config) {
		supportForcedPasswordChange = AuthenticationConfig.getBoolean(AuthenticationConfig.SUPPORT_FORCED_PASSWORD_CHANGE, false);
		if (supportForcedPasswordChange) {
			changePasswordUrl = AuthenticationConfig.getChangePasswordUrl();
			if (StringUtils.isBlank(changePasswordUrl)) {
				log.error("Authentication Config is set to support force password change, but url to change password has not been set, ignoring");
				supportForcedPasswordChange = false;
			}
			whiteList = AuthenticationConfig.getPasswordChangeWhiteList();
		}
	}

	@Override
	public void destroy() {
		supportForcedPasswordChange = false;
		changePasswordUrl = null;
		whiteList = null;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (supportForcedPasswordChange && !WebUtil.isWhiteListed(request, whiteList)) {
			User user = getAuthenticatedUser(request, response);
			if (user != null) {
				if (Boolean.parseBoolean(user.getUserProperty(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD))) {
					response.sendRedirect(changePasswordUrl);
				}
			}
		}

		if (!response.isCommitted()) {
			chain.doFilter(request, response);
		}
	}

	/**
	 * Return the current authenticated user, if present, or null if no user is currently authenticated
	 */
	protected User getAuthenticatedUser(HttpServletRequest request, HttpServletResponse response) {
		AuthenticationSession session = new AuthenticationSession(request, response);
		if (session.isUserAuthenticated()) {
			return session.getUserLogin().getUser();
		}
		return null;
	}
}
