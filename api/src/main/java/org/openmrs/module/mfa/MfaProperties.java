/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Context;
import org.openmrs.util.OpenmrsUtil;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Loads all configuration settings for the module from mfa.properties
 */
public class MfaProperties implements Serializable {

    // Available configuration parameters in mfa.properties
    public static final String MFA_PROPERTIES_FILE_NAME = "mfa.properties";
    public static final String MFA_ENABLED = "mfa.enabled";
    public static final String MFA_DISABLE_CONFIGURATION_CACHE = "mfa.disableConfigurationCache";
    public static final String MFA_UNAUTHENTICATED_URLS = "mfa.unauthenticatedUrls";
    public static final String AUTHENTICATORS_PRIMARY = "authenticators.primary";
    public static final String AUTHENTICATORS_SECONDARY= "authenticators.secondary";
    public static final String AUTH_NAME_VARIABLE = "{authName}";
    public static final String AUTHENTICATOR_TYPE = "authenticator." + AUTH_NAME_VARIABLE + ".type";
    public static final String AUTHENTICATOR_CONFIG = "authenticator." + AUTH_NAME_VARIABLE + ".config.";

    private static final Log log = LogFactory.getLog(MfaProperties.class);

    private Properties config;

    public MfaProperties() {
        config = getPropertiesFromFile();
    }

    public MfaProperties(Properties config) {
        this.config = config;
    }

    public String getProperty(String key) {
        return getConfig().getProperty(key);
    }

    public String getProperty(String key, String defaultValue) {
        return getConfig().getProperty(key, defaultValue);
    }

    public void setProperty(String key, String value) {
        getConfig().setProperty(key, value);
    }

    public Set<String> getKeys() {
        return getConfig().stringPropertyNames();
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        String val = getProperty(key);
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val);
    }

    public List<String> getStringList(String key) {
        List<String> ret = new ArrayList<>();
        String val = getProperty(key);
        if (StringUtils.isNotBlank(val)) {
            for (String s : val.split(",")) {
                ret.add(s);
            }
        }
        return ret;
    }

    public Properties getSubsetWithPrefix(String prefix, boolean stripPrefix) {
        Properties c = new Properties();
        for (String key : getKeys()) {
            if (key.startsWith(prefix)) {
                String value = getProperty(key);
                if (stripPrefix) {
                    key = key.substring(prefix.length());
                }
                c.put(key, value);
            }
        }
        return c;
    }

    // Configuration

    public boolean isMfaEnabled() {
        return getBoolean(MFA_ENABLED, false);
    }

    public boolean isConfigurationCacheDisabled() {
        return getBoolean(MFA_DISABLE_CONFIGURATION_CACHE, false);
    }

    public List<String> getUnauthenticatedUrlPatterns() {
        return getStringList(MFA_UNAUTHENTICATED_URLS);
    }

    public String getPrimaryAuthenticatorOption() {
        return getProperty(AUTHENTICATORS_PRIMARY);
    }

    public Authenticator getPrimaryAuthenticator() {
        return getAuthenticator(getPrimaryAuthenticatorOption());
    }

    public List<String> getSecondaryAuthenticatorOptions() {
        return getStringList(AUTHENTICATORS_SECONDARY);
    }

    public Authenticator getAuthenticator(String authName) {
        Authenticator authenticator = null;
        String authenticatorPropertyName = AUTHENTICATOR_TYPE.replace(AUTH_NAME_VARIABLE, authName);
        String authenticatorType = getProperty(authenticatorPropertyName);
        if (StringUtils.isNotBlank(authenticatorType)) {
            try {
                Class<?> clazz = Context.loadClass(authenticatorType);
                authenticator = (Authenticator) clazz.getDeclaredConstructor().newInstance();
            }
            catch (Exception e) {
                throw new RuntimeException("Unable to construct authenticator type: " + authenticatorType, e);
            }
        }
        String authenticatorConfigProp = AUTHENTICATOR_CONFIG.replace(AUTH_NAME_VARIABLE, authName);
        authenticator.configure(authName, getSubsetWithPrefix(authenticatorConfigProp, true));
        return authenticator;
    }

    // Loading

    public synchronized Properties getConfig() {
        if (config == null) {
            config = getPropertiesFromFile();
        }
        return config;
    }

    public synchronized Properties reloadConfig() {
        this.config = null;
        return getConfig();
    }

    public Properties getPropertiesFromFile() {
        Properties p = new Properties();
        File propertiesFile = new File(OpenmrsUtil.getApplicationDataDirectory(), MFA_PROPERTIES_FILE_NAME);
        if (propertiesFile.exists()) {
            OpenmrsUtil.loadProperties(p, propertiesFile);
        }
        else {
            log.warn("No mfa.properties file has been defined");
        }
        return p;
    }
}
