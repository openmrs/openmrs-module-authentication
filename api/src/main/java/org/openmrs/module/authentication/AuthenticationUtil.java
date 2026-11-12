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

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * This class provides utility methods for the authentication module
 */
public class AuthenticationUtil {

    // Excludes visually ambiguous characters (I/l/1, O/0)
    private static final String UPPER_CASE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ";

    private static final String LOWER_CASE_CHARS = "abcdefghijkmnopqrstuvwxyz";

    private static final String DIGIT_CHARS = "23456789";

    private static final String ALL_CHARS = UPPER_CASE_CHARS + LOWER_CASE_CHARS + DIGIT_CHARS;

    private static final int DEFAULT_PASSWORD_LENGTH = 20;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a random password of {@link #DEFAULT_PASSWORD_LENGTH} characters, suitable for use whenever a
     * user is created or has their password reset without a password being supplied directly.
     *
     * @return a randomly-generated password containing at least one upper-case letter, one lower-case letter,
     *         and one digit
     */
    public static String generateRandomPassword() {
        return generateRandomPassword(DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * @param length the length of the password to generate, which must be at least 3
     * @return a randomly-generated password of the given length, containing at least one upper-case letter,
     *         one lower-case letter, and one digit
     */
    public static String generateRandomPassword(int length) {
        if (length < 3) {
            throw new IllegalArgumentException("length must be at least 3");
        }
        List<Character> passwordChars = new ArrayList<>(length);
        passwordChars.add(randomCharFrom(UPPER_CASE_CHARS));
        passwordChars.add(randomCharFrom(LOWER_CASE_CHARS));
        passwordChars.add(randomCharFrom(DIGIT_CHARS));
        while (passwordChars.size() < length) {
            passwordChars.add(randomCharFrom(ALL_CHARS));
        }
        Collections.shuffle(passwordChars, SECURE_RANDOM);
        StringBuilder password = new StringBuilder(passwordChars.size());
        for (Character c : passwordChars) {
            password.append(c.charValue());
        }
        return password.toString();
    }

    private static char randomCharFrom(String chars) {
        return chars.charAt(SECURE_RANDOM.nextInt(chars.length()));
    }

    /**
     * @param val the value to parse
     * @param defaultValue the value to return if the value to parse is null or blank
     * @return the passed value, parsed to a boolean, or the default value if null
     */
    public static Boolean getBoolean(String val, boolean defaultValue) {
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
    public static Integer getInteger(String val, Integer defaultValue) {
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
