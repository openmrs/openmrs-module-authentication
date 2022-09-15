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
import org.openmrs.api.context.Context;
import org.openmrs.util.OpenmrsUtil;

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
    public static final String PREFIX = "mfa.";
    public static final String MFA_ENABLED = PREFIX + "enabled";
    public static final String MFA_DISABLE_CONFIGURATION_CACHE = PREFIX + "disableConfigurationCache";
    public static final String MFA_UNAUTHENTICATED_URLS = PREFIX + "unauthenticatedUrls";
    public static final String AUTHENTICATORS_PRIMARY = PREFIX + "authenticators.primary";
    public static final String AUTHENTICATORS_SECONDARY= PREFIX + "authenticators.secondary";
    public static final String AUTH_NAME_VARIABLE = "{authName}";
    public static final String AUTHENTICATOR_TYPE = PREFIX + "authenticator." + AUTH_NAME_VARIABLE + ".type";
    public static final String AUTHENTICATOR_CONFIG = PREFIX + "authenticator." + AUTH_NAME_VARIABLE + ".config.";

    private static Properties config;

    public static Properties getConfig() {
        if (config == null) {
            config = getPropertiesWithPrefix(Context.getRuntimeProperties(), PREFIX, false);
        }
        return config;
    }

    public static void setConfig(Properties config) {
        MfaProperties.config = config;
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
            for (String s : val.split(",")) {
                ret.add(s);
            }
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

    public static boolean isMfaEnabled() {
        return getBoolean(MFA_ENABLED, false);
    }

    public static boolean isConfigurationCacheDisabled() {
        return getBoolean(MFA_DISABLE_CONFIGURATION_CACHE, false);
    }

    public static List<String> getUnauthenticatedUrlPatterns() {
        return getStringList(MFA_UNAUTHENTICATED_URLS);
    }

    public static List<String> getPrimaryAuthenticatorOptions() {
        return getStringList(AUTHENTICATORS_PRIMARY);
    }

    public static Authenticator getDefaultPrimaryAuthenticator() {
        if (getPrimaryAuthenticatorOptions().isEmpty()) {
            return null;
        }
        return getAuthenticator(getPrimaryAuthenticatorOptions().get(0));
    }

    public static List<String> getSecondaryAuthenticatorOptions() {
        return getStringList(AUTHENTICATORS_SECONDARY);
    }

    public static Authenticator getAuthenticator(String authName) {
        String authenticatorPropertyName = AUTHENTICATOR_TYPE.replace(AUTH_NAME_VARIABLE, authName);
        String authenticatorConfigProp = AUTHENTICATOR_CONFIG.replace(AUTH_NAME_VARIABLE, authName);
        Authenticator authenticator = getClassInstance(authenticatorPropertyName, Authenticator.class);
        authenticator.configure(authName, getSubsetWithPrefix(authenticatorConfigProp, true));
        return authenticator;
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
