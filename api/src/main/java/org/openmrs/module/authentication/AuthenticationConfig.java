/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.apache.commons.lang.StringUtils;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.util.OpenmrsClassLoader;
import org.openmrs.util.OpenmrsUtil;

import java.io.Serializable;
import java.util.ArrayList;
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
     * If set to true, this indicates that users who have been set to require a password change are directed
     * to the corresponding `authentication.passwordChangeUrl` page before they can proceed into the system
     */
    public static final String SUPPORT_FORCED_PASSWORD_CHANGE = "authentication.supportForcedPasswordChange";

    /**
     * If `authentication.supportForcedPasswordChange` is to true, this indicates the url that users should be
     * redirected to if they are set to require their password changed at next login.
     */
    public static final String PASSWORD_CHANGE_URL = "authentication.passwordChangeUrl";

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
     * Some URL patterns should not result in a redirect to a challengeUrl, but rather should result in a 401
     * unauthorized response with the challengeUrl set as the Location header.  This is generally true for all requests
     * of RESTful endpoints that are interacting with the API in a single-page app rather than redirecting to new urls
     */
    public static final String NON_REDIRECT_URLS = "authentication.nonRedirectUrls";

    /**
     * URLs that might need to be made accessible without go through the password change authentication.
     */
    public static final String PASSWORD_CHANGE_WHITE_LIST = "authentication.passwordChangeWhiteList";

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

    private static final List<ClassLoader> classLoaders = new ArrayList<>();

    /**
     * @return the configured properties, loading from runtime properties if necessary
     */
    public static Properties getConfig() {
        if (config == null) {
            config = AuthenticationUtil.getPropertiesWithPrefix(Context.getRuntimeProperties(), PREFIX, false);
        }
        return config;
    }

    /**
     * @param classLoader a classLoader to add to the list of classLoaders that can resolve classes for instantiation
     */
    public static void registerClassLoader(ClassLoader classLoader) {
        AuthenticationConfig.classLoaders.add(classLoader);
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
        if (value == null) {
            getConfig().remove(key);
        }
        else {
            getConfig().setProperty(key, value);
        }
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
        return AuthenticationUtil.getBoolean(getProperty(key), defaultValue);

    }

    /**
     * @param key the configuration property to retrieve
     * @return the value of the property, parsed into a List, split by comma, or an empty list if not found
     */
    public static List<String> getStringList(String key) {
        return AuthenticationUtil.getStringList(getProperty(key), ",");
    }

    /**
     * @param key the configuration property to retrieve
     * @param type the type of class expected
     * @return a new instance of the given type of class, with a type identified by the value of the given property
     */
    public static <T> T getClassInstance(String key, Class<T> type) {
        Class<? extends T> clazz = getClass(key, type);
        if (clazz != null) {
            try {
                return clazz.getDeclaredConstructor().newInstance();
            }
            catch (Exception e) {
                throw new RuntimeException("Unable to instantiate class " + type);
            }
        }
        return null;
    }

    /**
     * @param key the configuration property to retrieve
     * @param ignoredType the type of class expected
     * @return a class of the given type, with a type identified by the value of the given property
     */
    @SuppressWarnings("unchecked")
    public static <T> Class<? extends T> getClass(String key, Class<T> ignoredType) {
        String className = config.getProperty(key);
        if (StringUtils.isNotBlank(className)) {
            List<ClassLoader> loaders = new ArrayList<>();
            loaders.add(OpenmrsClassLoader.getInstance());
            loaders.add(AuthenticationUtil.class.getClassLoader());
            loaders.addAll(classLoaders);
            for (ClassLoader loader : loaders) {
                try {
                    return (Class<? extends T>) loader.loadClass(className.trim());
                } catch (Throwable ignored) {
                }
            }
            throw new RuntimeException("Unable to load class: " + className);
        }
        return null;
    }

    /**
     * @param prefix the prefix to search on configuration properties
     * @param stripPrefix if true, this will remove the prefix in the resulting Properties
     * @return the configuration properties that start with the given prefix, without the prefix if stripPrefix is true
     */
    public static Properties getSubsetWithPrefix(String prefix, boolean stripPrefix) {
        return AuthenticationUtil.getPropertiesWithPrefix(config, prefix, stripPrefix);
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
     * @return the List of url patterns that should not result in a redirect upon authentication failure
     */
    public static List<String> getNonRedirectUrls() {
        List<String> nonRedirectUrls = getStringList(NON_REDIRECT_URLS);
        nonRedirectUrls.add("/ws/**/*");
        return nonRedirectUrls;
    }

     /**
     * @return the List of url patterns to allow without force password authentication redirection
     */
    public static List<String> getPasswordChangeWhiteList() {
        List<String> whiteList = getStringList(PASSWORD_CHANGE_WHITE_LIST);
        whiteList.add(getChangePasswordUrl());  // Add the change password URL to the whitelist
        return whiteList;
    }

    public static String getChangePasswordUrl() {
        return getConfig().getProperty(PASSWORD_CHANGE_URL);
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
        config = AuthenticationUtil.getPropertiesWithPrefix(runtimeProperties, PREFIX, false);
    }
}
