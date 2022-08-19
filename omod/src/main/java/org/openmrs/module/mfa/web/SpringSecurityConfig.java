/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.openmrs.module.mfa.web.LoginRedirectDsl.loginRedirectDsl;

/**
 * This class configures Spring security for the web layer The intention is for this to provide a
 * foundation upon which modules can enable additional security configuration By default, this
 * configuration will produce a SecurityFilterChain bean with default order, which means it will
 * execute last, after any other SecurityFilterChain bean that is declared with an explicit order
 * Modules that wish to apply different security filter chain rules can add their own
 * SecurityFilterChain beans to the context with an @Order annotation that indicates precedence
 * (lower order = higher prececence). See: <a href=
 * "https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#_multiple_httpsecurity"
 * > Spring security documentation </a> This configuration provides no authentication or
 * authorization checks at all, permitting access for all requests. However, the default
 * configuration of Spring Security does add a few additional security measures spring security adds
 * additional security measures to the web application by default. See: <a href=
 * "https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters"
 * > Spring security servlet security filters </a> Some of these security measures need to be
 * disabled in order to enable existing legacy functionality to work. This includes: * Disabling
 * CSRF (TODO: Determine if we can re-enable this, and whether this can replace the OWASP csrfguard
 * * Disabling nosniff for content type options, due to Javascript resources that contain JSTL (and
 * whose content type is set to text/html) to load successfully. See: <a href=
 * "https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/headers.html#headers-content-type-options"
 * > Spring Security Content-type-options </a>
 */
@EnableWebSecurity
public class SpringSecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.apply(loginRedirectDsl()).and()
			.authorizeRequests(authorize -> authorize.anyRequest().permitAll())
			.csrf().disable()
			.headers().contentTypeOptions().disable();
		return http.build();
	}
}
