/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.filter;

import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.json.JsonUtil;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.authscheme.OAuth2TokenCredentials;
import org.openmrs.module.authentication.authscheme.UserInfo;
import org.openmrs.module.authentication.web.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Properties;

import static org.openmrs.module.authentication.AuthenticationConfig.OAUTH_PROP_BEAN_NAME;

/**
 * Filter for authenticating oauth2 service accounts
 */
public class OAuth2ServiceAccountFilter implements Filter {
	
	private static final Logger log = LoggerFactory.getLogger(OAuth2ServiceAccountFilter.class);
	
	public static final String HEADER_NAME_AUTH = "Authorization";
	
	public static final String HEADER_NAME_X_JWT_ASSERT = "X-JWT-Assertion";
	
	public static final String SCHEME_BEARER = "Bearer";
	
	/**
	 * @see Filter#init(FilterConfig)
	 */
	@Override
	public void init(FilterConfig arg0) throws ServletException {
		log.debug("Initializing oauth2 service account login filter");
	}
	
	/**
	 * @see Filter#destroy()
	 */
	@Override
	public void destroy() {
		log.debug("Destroying oauth2 service account login filter");
	}
	
	/**
	 * @see Filter#doFilter(ServletRequest,
	 *      ServletResponse, FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
	        ServletException {
		
		if (request instanceof HttpServletRequest) {
			//TODO should we limit this authentication mechanism to webservice calls only?
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String headerValue = httpRequest.getHeader(HEADER_NAME_AUTH);
			String token;
			if (StringUtils.isNotBlank(headerValue)) {
				token = headerValue.substring(SCHEME_BEARER.length() + 1);
			} else {
				token = httpRequest.getHeader(HEADER_NAME_X_JWT_ASSERT);
			}
			
			if (StringUtils.isNotBlank(token)) {
				if (log.isDebugEnabled()) {
					log.debug("Found Authorization header on request");
				}
				
				String[] parts = token.split("\\.");
				//Ignore if this is not a JWT token
				if (parts.length == 3) {
					try {
						//for Service Account it's possible to use another property to retrieve the username
						Properties props = Context.getRegisteredComponent(OAUTH_PROP_BEAN_NAME, Properties.class);
						String serviceAccountProperty = props.getProperty(UserInfo.PROP_USERNAME_SERVICE_ACCOUNT, null);
						if (serviceAccountProperty != null) {
							props = (Properties) props.clone();
							props.put(UserInfo.PROP_USERNAME, serviceAccountProperty);
						}
						
						Claims claims = JwtUtils.parseAndVerifyToken(token, props);
						String userInfoJson = JsonUtil.toJson(claims);
						Context.authenticate(new OAuth2TokenCredentials(new UserInfo(props, userInfoJson), true));
					}
					catch (Throwable e) {
						//Ignore and let the API take care of authentication issues
						log.warn("Failed to authenticate user using oauth token", e);
					}
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Ignoring non JWT token");
					}
				}
			} else {
				if (log.isDebugEnabled()) {
					log.debug("No oauth token specified via supported header names");
				}
			}
		}
		
		chain.doFilter(request, response);
	}
}
