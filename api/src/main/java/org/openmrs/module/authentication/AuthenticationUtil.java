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

import org.apache.commons.collections.map.CaseInsensitiveMap;
import org.apache.commons.lang.StringUtils;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This class provides utility methods for the authentication module
 */
public class AuthenticationUtil {

    /**
     * @param val the value to parse
     * @param defaultValue the value to return if the value to parse is null or blank
     * @return the passed value, parsed to a boolean, or the default value if null
     */
    public static boolean getBoolean(String val, boolean defaultValue) {
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }

        return Boolean.parseBoolean(val);
    }

    /**
     * @param val the value to parse
     * @param defaultValue the value to return if the value to parse is null or blank
     * @return the passed value, parsed to a boolean, or the default value if null
     */
    public static int getInteger(String val, Integer defaultValue) {
        if (StringUtils.isBlank(val)) {
            return defaultValue;
        }
        return Integer.parseInt(val);
    }

    /**
     * @param val the string value to parse into a List of strings
     * @param delimiter the regex delimiter value
     * @return a List of strings resulting from splitting the passed val by the passed delimiter
     */
    public static List<String> getStringList(String val, String delimiter) {
        List<String> ret = new ArrayList<>();
        if (StringUtils.isNotBlank(val)) {
            ret.addAll(Arrays.asList(val.split(delimiter)));
        }
        return ret;
    }

    /**
     * @param prefix the prefix to search in the keys of the given Properties
     * @param stripPrefix if true, this will remove the prefix in the resulting Properties
     * @return the Properties whose keys start with the given prefix, without the prefix if stripPrefix is true
     */
    public static Map<String, String> getPropertiesWithPrefix(Map<?, ?> properties, String prefix, boolean stripPrefix) {
        @SuppressWarnings("unchecked")
        Map<String, String> ret = new CaseInsensitiveMap();
        for (Object keyObj : properties.keySet()) {
            if (keyObj instanceof String) {
                String key = (String) keyObj;
                if (key.startsWith(prefix)) {
                    Object value = properties.get(key);
                    if (value instanceof String) {
                        if (stripPrefix) {
                            key = key.substring(prefix.length());
                        }
                        ret.put(key, (String) value);
                    }
                }
            }
        }

        return ret;
    }

    /**
     * Formats the given date as "yyyy-MM-dd'T'HH:mm:ss,SSS", or returns null if the date is null
     * @param date the date to format
     * @return the date formatted as ISO8601 or null if the passed date is null
     */
    public static String formatIsoDate(Date date) {
        if (date == null) {
            return null;
        }
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss,SSS").format(date);
    }
}
