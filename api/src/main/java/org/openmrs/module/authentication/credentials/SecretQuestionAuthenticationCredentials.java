/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.credentials;

import org.openmrs.User;

/**
 * Credentials that enable validating a user's secret question and answer
 * This is generally intended to be used as a secondary authentication factor
 */
public class SecretQuestionAuthenticationCredentials extends AuthenticationCredentials {

    private final String schemeId;
    private final User user;
    private final String question;
    private final String answer;

    public SecretQuestionAuthenticationCredentials(String schemeId, User user, String question, String answer) {
        this.schemeId = schemeId;
        this.user = user;
        this.question = question;
        this.answer = answer;
    }

    @Override
    public String getAuthenticationScheme() {
        return schemeId;
    }

    @Override
    public String getClientName() {
        return user.getUsername();
    }

    public User getUser() {
        return user;
    }

    public String getSchemeId() {
        return schemeId;
    }

    public String getQuestion() {
        return question;
    }

    public String getAnswer() {
        return answer;
    }
}
