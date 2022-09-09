/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.openmrs.module.mfa.AuthenticationContext;
import org.openmrs.module.mfa.MfaProperties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Wrapper class for an HttpSession that provides access to the MfaCredentials
 */
public class AuthenticationSession {

    public static final String CONTEXT_SESSION_KEY = "__mfa_authentication_context";

    private HttpServletRequest request;
    private HttpServletResponse response;

    public AuthenticationSession(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public AuthenticationContext getAuthenticationContext() {
        AuthenticationContext context = (AuthenticationContext) request.getSession().getAttribute(CONTEXT_SESSION_KEY);
        if (context == null) {
            context = new AuthenticationContext(new MfaProperties());
            setAuthenticationContext(context);
        }
        return context;
    }

    public String getRequestParam(String name) {
        return request.getParameter(name);
    }

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        request.getSession().setAttribute(CONTEXT_SESSION_KEY, authenticationContext);
    }

    public void reset() {
        request.getSession().removeAttribute(CONTEXT_SESSION_KEY);
    }

}
