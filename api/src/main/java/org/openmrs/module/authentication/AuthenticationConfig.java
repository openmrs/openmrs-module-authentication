/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.apache.commons.lang.StringUtils;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.scheme.ConfigurableAuthenticationScheme;
import org.openmrs.util.OpenmrsUtil;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Loads all configuration settings for the module from runtime properties
 */
public class AuthenticationConfig implements Serializable {

    // Available configuration parameters in runtime properties
    public static final String PREFIX = "authentication.";
    public static final String SCHEME = "scheme";
    public static final String AUTHENTICATION_SCHEME = PREFIX + SCHEME;
    public static final String SETTINGS_PREFIX = PREFIX + "settings.";
    public static final String SETTINGS_CACHED = SETTINGS_PREFIX + "cached";
    public static final String FILTER_PREFIX = PREFIX + "filter.";
    public static final String FILTER_ENABLED = FILTER_PREFIX + "enabled";
    public static final String FILTER_SKIP_PATTERNS = FILTER_PREFIX + "skipPatterns";
    public static final String AUTH_NAME_VARIABLE = "{authName}";
    public static final String AUTHENTICATOR_TYPE = AUTHENTICATION_SCHEME + "." + AUTH_NAME_VARIABLE + ".type";
    public static final String AUTHENTICATOR_CONFIG = AUTHENTICATION_SCHEME + "." + AUTH_NAME_VARIABLE + ".config.";

    private static Properties config;

    public static Properties getConfig() {
        if (config == null) {
            config = getPropertiesWithPrefix(Context.getRuntimeProperties(), PREFIX, false);
        }
        return config;
    }

    public static void setConfig(Properties config) {
        AuthenticationConfig.config = config;
    }

    public static String getProperty(String key) {
        return getConfig().getProperty(key);
    }

    public static String getProperty(String key, String defaultValue) {
        return getConfig().getProperty(key, defaultValue);
    }

    public static void setProperty(String key, String value) {
        getConfig().setProperty(key, value);
    }

    public static Set<String> getKeys() {
        return getConfig().stringPropertyNames();
    }

    public static boolean getBoolean(String key, boolean defaultValue) {
        String val = getProperty(key);
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val);
    }

    public static List<String> getStringList(String key) {
        List<String> ret = new ArrayList<>();
        String val = getProperty(key);
        if (StringUtils.isNotBlank(val)) {
            ret.addAll(Arrays.asList(val.split(",")));
        }
        return ret;
    }

    public static <T> T getClassInstance(String key, Class<T> type) {
        T ret = null;
        Class<? extends T> clazz = getClass(key, type);
        if (clazz != null) {
            try {
                ret = (T) clazz.getDeclaredConstructor().newInstance();
            }
            catch (Exception e) {
                throw new RuntimeException("Unable to instantiate class " + type);
            }
        }
        return ret;
    }

    public static <T> Class<? extends T> getClass(String key, Class<T> type) {
        Class<? extends T> ret = null;
        try {
            String className = config.getProperty(key);
            if (StringUtils.isNotBlank(className)) {
                ret = (Class<? extends T>) Context.loadClass(className);
            }
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to load class " + type);
        }
        return ret;
    }

    public static Properties getSubsetWithPrefix(String prefix, boolean stripPrefix) {
        return getPropertiesWithPrefix(config, prefix, stripPrefix);
    }

    // Configuration

    public static boolean isFilterEnabled() {
        return getBoolean(FILTER_ENABLED, false);
    }

    public static boolean isConfigurationCached() {
        return getBoolean(SETTINGS_CACHED, true);
    }

    public static List<String> getFilterSkipPatterns() {
        return getStringList(FILTER_SKIP_PATTERNS);
    }

    public static AuthenticationScheme getAuthenticationScheme(String authName) {
        String authenticatorPropertyName = AUTHENTICATOR_TYPE.replace(AUTH_NAME_VARIABLE, authName);
        String authenticatorConfigProp = AUTHENTICATOR_CONFIG.replace(AUTH_NAME_VARIABLE, authName);
        AuthenticationScheme scheme = getClassInstance(authenticatorPropertyName, AuthenticationScheme.class);
        if (scheme instanceof ConfigurableAuthenticationScheme) {
            ConfigurableAuthenticationScheme configScheme = (ConfigurableAuthenticationScheme) scheme;
            configScheme.configure(authName, getSubsetWithPrefix(authenticatorConfigProp, true));
        }
        return scheme;
    }

    public static synchronized void reloadConfigFromRuntimeProperties(String applicationName) {
        config = getPropertiesWithPrefix(OpenmrsUtil.getRuntimeProperties(applicationName), PREFIX, false);
    }

    private static Properties getPropertiesWithPrefix(Properties properties, String prefix, boolean stripPrefix) {
        Properties ret = new Properties();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(prefix)) {
                String value = properties.getProperty(key);
                if (stripPrefix) {
                    key = key.substring(prefix.length());
                }
                ret.put(key, value);
            }
        }
        return ret;
    }
}
