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

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * This class allows us to inject our custom AuthenticationFilter into the springSecurityFilterChain
 * that is executed by Spring Security. We could eliminate this class and add the
 * AuthenticationFilter to config.xml directly, either before or after the springSecurityFilterChain
 * filter, but this allows us greater control over when exactly it is executed in relation to other
 * filters in the springSecurityFilterChain, and also provides additional capabilities, including
 * access to the Application Context and the HttpSecurity object <a href=
 * "https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#jc-custom-dsls"
 * > See reference here on Custom DSLs </a>
 */
public class LoginRedirectDsl extends AbstractHttpConfigurer<LoginRedirectDsl, HttpSecurity> {
	
	@Override
	public void init(HttpSecurity http) {
	}
	
	@Override
	public void configure(HttpSecurity http) {
		AuthenticationFilter authenticationFilter = new AuthenticationFilter();
		// TODO: Determine if this is the right place.  See order of filters here:
		// https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters
		http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}
	
	public static LoginRedirectDsl loginRedirectDsl() {
		return new LoginRedirectDsl();
	}
}
