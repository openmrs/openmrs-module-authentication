/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.convert.DefaultListDelimiterHandler;
import org.openmrs.util.OpenmrsUtil;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Loads configuration settings for the module
 */
@Component
public class MfaConfiguration {
	
	public static final String MFA_PROPERTIES_FILE_NAME = "mfa.properties";
	
	public static final String CONFIGURATION_CACHE_ENABLED = "configuration.cacheEnabled";
	public static final String FILTER_ENABLED = "filter.enabled";
	public static final String FILTER_UNAUTHENTICATED_URLS = "filter.unauthenticatedUrls";
	public static final String LOGIN_URL = "filter.loginUrl";
	
	private PropertiesConfiguration cache;
	
	public MfaConfiguration() {
	}

	public String getString(String propertyName, String defaultValue) {
		return getConfiguration().getString(propertyName, defaultValue);
	}

	public boolean getBoolean(String propertyName, boolean defaultValue) {
		return getConfiguration().getBoolean(propertyName, defaultValue);
	}

	public List<String> getStringList(String propertyName) {
		List<String> val = getConfiguration().getList(String.class, propertyName);
		return val == null ? new ArrayList<>() : val;
	}
	
	public void setConfigurationCache(Properties properties) {
		this.cache = getConfiguration(properties);
	}

	protected synchronized Configuration getConfiguration() {
		if (cache != null) {
			return cache;
		}
		Properties properties = new Properties();
		File propertiesFile = new File(OpenmrsUtil.getApplicationDataDirectoryAsFile(), MFA_PROPERTIES_FILE_NAME);
		if (propertiesFile.exists()) {
			OpenmrsUtil.loadProperties(properties, propertiesFile);
		}
		PropertiesConfiguration configuration = getConfiguration(properties);
		if (configuration.getBoolean(CONFIGURATION_CACHE_ENABLED, true)) {
			cache = configuration;
		}
		return configuration;
	}

	/**
	 * @return a PropertiesConfiguration instance for the given Properties
	 */
	private PropertiesConfiguration getConfiguration(Properties properties) {
		PropertiesConfiguration configuration = new PropertiesConfiguration();
		configuration.setListDelimiterHandler(new DefaultListDelimiterHandler(','));
		for (String propertyName : properties.stringPropertyNames()) {
			configuration.setProperty(propertyName, properties.getProperty(propertyName));
		}
		return configuration;
	}
}
