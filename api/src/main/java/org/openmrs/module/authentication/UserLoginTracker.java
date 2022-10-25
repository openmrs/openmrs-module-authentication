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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class maintains a UserLogins that are tracked across the application.  The primary purpose is to
 * maintain a collection of active UserLogin instances that represent the currently logged-in users, and to
 * maintain a ThreadLocal of UserLogin instances to enable tracking a particular UserLogin throughout the
 * lifetime of a thread
 */
public class UserLoginTracker {

    private static final ThreadLocal<UserLogin> threadLogins = new ThreadLocal<>();
    private static final Map<String, UserLogin> activeLogins = Collections.synchronizedMap(new LinkedHashMap<>());

    /**
     * This method should be called in order to register the given UserLogin on the current thread
     * To guard against memory leaks, this should be paired with remove()
     * @param userLogin the UserLogin to set on the thread
     */
    public static void setLoginOnThread(UserLogin userLogin) {
        threadLogins.set(userLogin);
    }

    /**
     * This method should be called in order to remove the given UserLogin from the current thread
     * Typically, this method will be paired with set to guard against memory leaks
     */
    public static void removeLoginFromThread() {
        threadLogins.remove();
    }

    /**
     * @return the UserLogin that has been associated with the current Thread
     */
    public static UserLogin getLoginOnThread() {
        return threadLogins.get();
    }

    /**
     * This method should be called after successful login to track this UserLogin as an active login.
     * To guard against memory leaks, this should pair with remove(UserLogin)
     * @param userLogin the UserLogin to add
     */
    public static void addActiveLogin(UserLogin userLogin) {
        activeLogins.put(userLogin.getLoginId(), userLogin);
    }

    /**
     * This method should be called in order to remove the given UserLogin from the set of logged-in users
     * To guard against memory leaks, this should pair with add(UserLogin)
     * @param userLogin the UserLogin to remove
     */
    public static void removeActiveLogin(UserLogin userLogin) {
        activeLogins.remove(userLogin.getLoginId());
    }

    /**
     * @return a Collection of UserLogins, defined as those that have been logged in and not logged out or expired
     * The Map returned is keyed on the loginId of the UserLogin
     */
    public static Map<String, UserLogin> getActiveLogins() {
        return Collections.unmodifiableMap(activeLogins);
    }

}
