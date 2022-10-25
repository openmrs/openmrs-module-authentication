/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.UserService;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.module.authentication.AuthenticationCredentials;

import java.util.Properties;

/**
 * This is an implementation of a WebAuthenticationScheme that is intended to be used as a secondary authentication
 * scheme, and validates that the provided answer matches the stored answer for the secret question for the user
 * This scheme supports configuration parameters that enable implementations to utilize it with their own pages
 * This includes the ability to configure the `loginPage` that the user should be taken to, as well as the
 * `questionParam` and `answerParam` that should be read from the http request submission to authenticate.
 */
public class SecretQuestionAuthenticationScheme implements WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String QUESTION_PARAM = "questionParam";
    public static final String ANSWER_PARAM = "answerParam";

    public static final String QUESTION = "question";
    public static final String ANSWER = "answer";

    protected String schemeId;
    protected String loginPage;
    protected String questionParam;
    protected String answerParam;

    public SecretQuestionAuthenticationScheme() {
        this.schemeId = getClass().getName();
    }

    @Override
    public String getSchemeId() {
        return schemeId;
    }

    @Override
    public void configure(String schemeId, Properties config) {
        this.schemeId = schemeId;
        loginPage = config.getProperty(LOGIN_PAGE, "/module/authentication/secretQuestion.htm");
        questionParam = config.getProperty(QUESTION_PARAM, QUESTION);
        answerParam = config.getProperty(ANSWER_PARAM, ANSWER);
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    @Override
    public AuthenticationCredentials getCredentials(AuthenticationSession session) {
        AuthenticationCredentials credentials = session.getUserLogin().getUnvalidatedCredentials(schemeId);
        if (credentials != null) {
            return credentials;
        }
        String question = session.getRequestParam(questionParam);
        String answer = session.getRequestParam(answerParam);
        if (StringUtils.isNotBlank(question) && StringUtils.isNotBlank(answer)) {
            User candidateUser = session.getUserLogin().getUser();
            credentials = new SecretQuestionAuthenticationCredentials(candidateUser, question, answer);
            session.getUserLogin().addUnvalidatedCredentials(credentials);
            return credentials;
        }
        return null;
    }

    @Override
    public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {

        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof SecretQuestionAuthenticationCredentials)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        SecretQuestionAuthenticationCredentials c = (SecretQuestionAuthenticationCredentials) credentials;

        if (c.user == null || StringUtils.isBlank(c.question) || StringUtils.isBlank(c.answer)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        String expectedQuestion = getSecretQuestion(c.user);
        if (StringUtils.isBlank(expectedQuestion) || !expectedQuestion.equalsIgnoreCase(c.question)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }
        if (!isSecretAnswer(c.user, c.answer)) {
            throw new ContextAuthenticationException("authentication.error.invalidCredentials");
        }

        return new BasicAuthenticated(c.user, credentials.getAuthenticationScheme());
    }

    /**
     * @see UserService#getSecretQuestion(User)
     */
    protected String getSecretQuestion(User user) {
        return Context.getUserService().getSecretQuestion(user);
    }

    /**
     * @see UserService#isSecretAnswer(User, String)
     */
    protected boolean isSecretAnswer(User user, String answer) {
        return Context.getUserService().isSecretAnswer(user, answer);
    }

    /**
     * Credentials inner class, to enable access and visibility of credential details to be limited to scheme
     */
    public class SecretQuestionAuthenticationCredentials implements AuthenticationCredentials {

        protected final User user;
        protected final String question;
        protected final String answer;

        @Override
        public String getAuthenticationScheme() {
            return schemeId;
        }

        protected SecretQuestionAuthenticationCredentials(User user, String question, String answer) {
            this.user = user;
            this.question = question;
            this.answer = answer;
        }

        @Override
        public String getClientName() {
            return user == null ? null : user.getUsername();
        }
    }
}
