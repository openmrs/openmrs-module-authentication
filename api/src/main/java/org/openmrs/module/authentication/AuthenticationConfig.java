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
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.scheme.ConfigurableAuthenticationScheme;
import org.openmrs.util.OpenmrsUtil;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * This class provides access to all authentication configuration settings
 * By default, this will load settings from the OpenMRS runtime properties, but can also be set programmatically
 */
public class AuthenticationConfig implements Serializable {

    /**
     * All configuration used by this module should start with `authentication` as a namespace
     */
    public static final String PREFIX = "authentication";

    /**
     * All configured authentication schemes are identified by a unique {schemeId} in the configuration
     */
    public static final String SCHEME_ID = "{schemeId}";

    /**
     * This property determines which authentication scheme is used
     * This enables implementations to configure the preferred authentication scheme at runtime
     * If not specified, then the module will default to the core UsernamePasswordAuthenticationScheme
     * This property should reference one of the {schemeId} values that identify a particular configured scheme
     * See SCHEME_TYPE and SCHEME_CONFIG below
     */
    public static final String SCHEME = "authentication.scheme";

    /**
     * By default, all configuration settings are loaded at startup and cached.
     * Subsequent changes to configuration in runtime properties will not take effect until an application restart
     * This property enables changing this behavior.  By setting this to `false`, settings will be reloaded from
     * the OpenMRS runtime properties file for every new HTTP request.
     * This is expected to be used only in development or testing, not in production, due to performance impacts.
     */
    public static final String SETTINGS_CACHED = "authentication.settings.cached";

    /**
     * If the configured `authentication.scheme` is a `WebAuthenticationScheme`, then by default all HTTP requests
     * will be blocked and redirected to the appropriate `challengeUrl` specified by the `WebAuthenticationScheme`.
     * In order to enable these `challengeUrl` pages to render without themselves redirecting for authentication in
     * an endless loop, this configuration setting allows configuration of a comma-delimited list of url patterns
     * that should not result in redirect for authentication.  This property can also be used for any additional
     * URLs that might need to be made accessible without authentication.
     */
    public static final String WHITE_LIST = "authentication.whiteList";

    /**
     * All AuthenticationScheme instances must be configured with, at minimum, a property that maps a particular
     * {schemeId} to a particular AuthenticationScheme class fully-specified name
     * Eg `authentication.scheme.basic.type = org.openmrs.module.authentication.web.BasicWebAuthenticationScheme`
     */
    public static final String SCHEME_TYPE_TEMPLATE = "authentication.scheme.{schemeId}.type";

    /**
     * If a particular AuthenticationScheme instance requires configuration, each configuration property
     * can be specified using a property with this prefix, followed by the name of the configuration property
     * Eg `authentication.scheme.basic.config.loginPage = /module/authentication/basic.htm`
     */
    public static final String SCHEME_CONFIG_PREFIX_TEMPLATE = "authentication.scheme.{schemeId}.config.";

    private static Properties config;

    /**
     * @return the configured properties, loading from runtime properties if necessary
     */
    public static Properties getConfig() {
        if (config == null) {
            config = getPropertiesWithPrefix(Context.getRuntimeProperties(), PREFIX, false);
        }
        return config;
    }

    /**
     * @param config sets the configuration with the given Properties
     */
    public static void setConfig(Properties config) {
        AuthenticationConfig.config = config;
    }

    /**
     * @param key the configuration property to retrieve
     * @return the value of the given configuration property
     */
    public static String getProperty(String key) {
        return getConfig().getProperty(key);
    }

    /**
     * @param key the configuration property to retrieve
     * @param defaultValue the value to return if the value for the given configuration property is null
     * @return the value of the given configuration property or the defaultValue if null
     */
    public static String getProperty(String key, String defaultValue) {
        return getConfig().getProperty(key, defaultValue);
    }

    /**
     * @param key the configuration key to update
     * @param value the value to update for the given configuration key
     */
    public static void setProperty(String key, String value) {
        getConfig().setProperty(key, value);
    }

    /**
     * @return all configuration properties currently configured
     */
    public static Set<String> getKeys() {
        return getConfig().stringPropertyNames();
    }

    /**
     * @param key the configuration property to retrieve
     * @param defaultValue the value to return if the value for the given configuration property is null
     * @return the value of the given key, parsed to a boolean, or the default value if null
     */
    public static boolean getBoolean(String key, boolean defaultValue) {
        String val = getProperty(key);
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val);
    }

    /**
     * @param key the configuration property to retrieve
     * @return the value of the property, parsed into a List, split by comma, or an empty list if not found
     */
    public static List<String> getStringList(String key) {
        List<String> ret = new ArrayList<>();
        String val = getProperty(key);
        if (StringUtils.isNotBlank(val)) {
            ret.addAll(Arrays.asList(val.split(",")));
        }
        return ret;
    }

    /**
     * @param key the configuration property to retrieve
     * @param type the type of class expected
     * @return a new instance of the given type of class, with a type identified by the value of the given property
     */
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

    /**
     * @param key the configuration property to retrieve
     * @param type the type of class expected
     * @return a class of the given type, with a type identified by the value of the given property
     */
    @SuppressWarnings("unchecked")
    public static <T> Class<? extends T> getClass(String key, Class<T> type) {
        Class<?> ret = null;
        try {
            String className = config.getProperty(key);
            if (StringUtils.isNotBlank(className)) {
                try {
                    ret = Context.loadClass(className);
                }
                catch (Throwable t) {
                    ret = AuthenticationConfig.class.getClassLoader().loadClass(className);
                }
            }
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to load class " + type);
        }
        return (Class<? extends T>) ret;
    }

    /**
     * @param prefix the prefix to search on configuration properties
     * @param stripPrefix if true, this will remove the prefix in the resulting Properties
     * @return the configuration properties that start with the given prefix, without the prefix if stripPrefix is true
     */
    public static Properties getSubsetWithPrefix(String prefix, boolean stripPrefix) {
        return getPropertiesWithPrefix(config, prefix, stripPrefix);
    }

    // Configuration

    /**
     * @return true if configuration cache is enabled
     */
    public static boolean isConfigurationCacheEnabled() {
        return getBoolean(SETTINGS_CACHED, true);
    }

    /**
     * @return the List of url patterns to allow without authentication redirection
     */
    public static List<String> getWhiteList() {
        return getStringList(WHITE_LIST);
    }

    /**
     * @return the configured authentication scheme, defaulting to a UsernamePasswordAuthenticationScheme if not found
     */
    public static AuthenticationScheme getAuthenticationScheme() {
        String scheme = AuthenticationConfig.getProperty(SCHEME);
        if (StringUtils.isBlank(scheme)) {
            return new UsernamePasswordAuthenticationScheme();
        }
        else {
            return getAuthenticationScheme(scheme);
        }
    }

    /**
     * @param schemeId the {schemeId} that identifies the authentication scheme configuration in the properties
     * @return a configured AuthenticationScheme given configuration properties
     */
    public static AuthenticationScheme getAuthenticationScheme(String schemeId) {
        String schemeTypeProperty = SCHEME_TYPE_TEMPLATE.replace(SCHEME_ID, schemeId);
        String schemeConfigPropertyPrefix = SCHEME_CONFIG_PREFIX_TEMPLATE.replace(SCHEME_ID, schemeId);
        AuthenticationScheme scheme = getClassInstance(schemeTypeProperty, AuthenticationScheme.class);
        if (scheme instanceof ConfigurableAuthenticationScheme) {
            ConfigurableAuthenticationScheme configScheme = (ConfigurableAuthenticationScheme) scheme;
            configScheme.configure(schemeId, getSubsetWithPrefix(schemeConfigPropertyPrefix, true));
        }
        return scheme;
    }

    /**
     * Reloads the configuration from runtime properties
     * @param applicationName the application name from OpenMRS that identifies the name of the runtime properties file
     */
    public static synchronized void reloadConfigFromRuntimeProperties(String applicationName) {
        Properties runtimeProperties = OpenmrsUtil.getRuntimeProperties(applicationName);
        config = getPropertiesWithPrefix(runtimeProperties, PREFIX, false);
    }

    /**
     * @param prefix the prefix to search in the keys of the given Properties
     * @param stripPrefix if true, this will remove the prefix in the resulting Properties
     * @return the Properties whose keys start with the given prefix, without the prefix if stripPrefix is true
     */
    public static Properties getPropertiesWithPrefix(Properties properties, String prefix, boolean stripPrefix) {
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
