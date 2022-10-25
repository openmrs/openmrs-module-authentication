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

import java.io.Serializable;
import java.util.Date;

/**
 * Represents a particular event during the authentication process
 */
public class AuthenticationEvent implements Serializable {

    public static final String AUTHENTICATION_SUCCEEDED = "AUTHENTICATION_SUCCEEDED";
    public static final String AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
    public static final String LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String LOGIN_EXPIRED = "LOGIN_EXPIRED";
    public static final String LOGOUT_SUCCEEDED = "LOGOUT_SUCCEEDED";
    public static final String LOGOUT_FAILED = "LOGOUT_FAILED";

    private final String event;
    private final Date eventDate;

    public AuthenticationEvent(String event) {
        this.event = event;
        this.eventDate = new Date();
    }

    @Override
    public String toString() {
        return event + " - " + AuthenticationUtil.formatIsoDate(eventDate);
    }

    public String getEvent() {
        return event;
    }

    public Date getEventDate() {
        return eventDate;
    }
}
