/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.springframework.stereotype.Component;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.context.support.XmlWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration.Dynamic;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import java.util.EnumSet;

/**
 * See 'Limitations' and 'Alternatives' at the below wiki page.
 * 
 * @see <a href="https://wiki.openmrs.org/display/docs/Module+Servlets">OpenMRS documentation
 *      related to Module and Servlets</a>
 */
@Component
public class CustomDispatcherServlet implements ServletContextAware {
	
	private final Log log = LogFactory.getLog(getClass());
	
	@Override
	public void setServletContext(ServletContext servletContext) {
		
		try {
			XmlWebApplicationContext appContext = new XmlWebApplicationContext();
			appContext.setConfigLocation("classpath*:/" + AuthenticationConfig.PREFIX
			        + "/webApplicationContext.xml");
			final String servletName = AuthenticationConfig.PREFIX;
			
			ServletRegistration servletReg = servletContext.addServlet(servletName, new DispatcherServlet(appContext));
			servletReg.addMapping("/oauth2login");
			
			log.info("Servlet '" + servletName + "' with webModuleApplicationContext config added successfully.");
			
			Dynamic filter = servletContext.addFilter("springSecurityFilterChain",
			    new org.springframework.web.filter.DelegatingFilterProxy());
			filter.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");
			
			log.info("Filter 'springSecurityFilterChain' added successfully.");
		}
		catch (Exception ex) {
			// TODO need a work around for: java.lang.IllegalStateException: Started
			// Unable to configure mapping for servlet because this servlet context has
			// already been initialized.
			// This happens on running openmrs after InitializationFilter or UpdateFilter
			// hence requiring a restart to see any page other than index.htm
			// After a restart, all mappings will then happen within
			// Listener.contextInitialized()
			log.error(ex.getStackTrace());
		}
	}
}
