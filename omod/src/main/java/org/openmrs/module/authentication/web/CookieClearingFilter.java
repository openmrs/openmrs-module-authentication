package org.openmrs.module.authentication.web;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.web.WebConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This servlet filter exists to remove session cookies when a user logs out.
 * <p/>
 * This filter is configurable at runtime using the following properties:
 * <ul>
 *     <li><tt>authentication.cookies.clearOnLogout = true | false </tt> determines whether to clear cookies on logout. If
 *     not set to <tt>true</tt>, this filter takes no actions.</li>
 *     <li><tt>authentication.cookies.toClear = comma separated list of cookies to clear</tt>
 *     determines the cookies we will try to clear. If unset, no action will be taken. If set, the named cookies will only be
 *     cleared if they are present on the incoming request.</li>
 * </ul>
 */
public class CookieClearingFilter implements Filter {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	
	}
	
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		
		if (servletRequest instanceof HttpServletRequest && servletResponse instanceof HttpServletResponse) {
			HttpServletRequest request = (HttpServletRequest) servletRequest;
			HttpServletResponse response = (HttpServletResponse) servletResponse;
			
			if (!AuthenticationConfig.isConfigurationCacheEnabled()) {
				AuthenticationConfig.reloadConfigFromRuntimeProperties(WebConstants.WEBAPP_NAME);
			}
			
			// if an earlier filter has already written a response, we cannot do anything
			if (response.isCommitted()) {
				filterChain.doFilter(servletRequest, servletResponse);
				return;
			}
			
			boolean isEnabled = AuthenticationConfig.getBoolean("authentication.cookies.clearOnLogout", false);
			String[] cookiesToClear = new String[0];
			if (isEnabled) {
				String cookiesToClearSetting = AuthenticationConfig.getProperty("authentication.cookies.toClear", "");
				isEnabled = StringUtils.isNotBlank(cookiesToClearSetting);
				if (isEnabled) {
					cookiesToClear = Arrays.stream(cookiesToClearSetting.split("\\s*,\\s*")).map(String::trim).toArray(
							String[]::new);
				}
			}
			
			boolean requestHasSession = false;
			if (isEnabled) {
				// we need to track whether this request initially was part of a session
				// if it was and there is no valid request at the end of the session, we clear the session cookies
				requestHasSession = request.getRequestedSessionId() != null;
			}
			
			// handle the request
			filterChain.doFilter(request, response);
			
			if (isEnabled && !response.isCommitted()) {
				HttpSession session = request.getSession(false);
				// session was invalidated
				if (session == null && requestHasSession) {
					for (Cookie cookie : request.getCookies()) {
						for (String cookieToClear : cookiesToClear) {
							if (cookieToClear.equalsIgnoreCase(cookie.getName())) {
								// NB This doesn't preserve the HttpOnly flag, but it seems irrelevant since Max-Age: 0 expires
								// the cookie, i.e., a well-behaved user agent will throw it away and, in any case, we delete
								// the value
								Cookie clearedCookie = (Cookie) cookie.clone();
								clearedCookie.setValue(null);
								clearedCookie.setMaxAge(0);
								response.addCookie(clearedCookie);
								break;
							}
						}
					}
				}
			}
		} else {
			filterChain.doFilter(servletRequest, servletResponse);
		}
	}
	
	@Override
	public void destroy() {
	
	}
}
