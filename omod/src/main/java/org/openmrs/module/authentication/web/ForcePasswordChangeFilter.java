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

import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.util.OpenmrsConstants;

/**
 * This filter checks if an authenticated user has been flagged by the admin to change his password
 * on first/subsequent login. It will intercept any requests made to a *.html or a *.form to force
 * the user to change his password.
 */
public class ForcePasswordChangeFilter implements Filter {
	
	private String excludeURL;
	
	private String changePasswordForm;
	
	private FilterConfig config;
		
	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
	}
	
	/**
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
	 *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException,
	        ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

	    if (WebUtil.isWhiteListed(request, AuthenticationConfig.getPasswordChangeWhiteList())) {
            chain.doFilter(request, response);
            return;
        }
		AuthenticationSession session = getAuthenticationSession(request, response);
		UserLogin userLogin = session.getUserLogin();
		if (userLogin.isUserAuthenticated() && 
		    Boolean.parseBoolean(userLogin.getUser().getUserProperties().get(OpenmrsConstants.USER_PROPERTY_CHANGE_PASSWORD))) {
		 	config.getServletContext().getRequestDispatcher(changePasswordForm).forward(request, response);
		 } else {
		 	chain.doFilter(request, response);
		 }
	}
	
	
	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {
		this.config = config;
		excludeURL = config.getInitParameter("excludeURL");
		changePasswordForm = config.getInitParameter("changePasswordForm");
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