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
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.UserLogin;

import java.util.Map;

/**
 * This is an implementation of a WebAuthenticationScheme that is intended to be used as a secondary authentication
 * scheme, and validates that the provided answer matches the stored answer for the secret question for the user
 * This scheme supports configuration parameters that enable implementations to utilize it with their own pages
 * This includes the ability to configure the `loginPage` that the user should be taken to, as well as the
 * `questionParam` and `answerParam` that should be read from the http request submission to authenticate.
 */
public class SecretQuestionAuthenticationScheme extends WebAuthenticationScheme {

    protected final Log log = LogFactory.getLog(getClass());

    public static final String LOGIN_PAGE = "loginPage";
    public static final String QUESTION_PARAM = "questionParam";
    public static final String ANSWER_PARAM = "answerParam";

    public static final String QUESTION = "question";
    public static final String ANSWER = "answer";

    protected String loginPage;
    protected String questionParam;
    protected String answerParam;

    @Override
    public void configure(String schemeId, Map<String, String> config) {
        super.configure(schemeId, config);
        loginPage = config.getOrDefault(LOGIN_PAGE, "/loginWithSecret.htm");
        questionParam = config.getOrDefault(QUESTION_PARAM, QUESTION);
        answerParam = config.getOrDefault(ANSWER_PARAM, ANSWER);
    }

    /**
     * @see WebAuthenticationScheme#isUserConfigurationRequired(User)
     */
    @Override
    public boolean isUserConfigurationRequired(User user) {
        return StringUtils.isBlank(Context.getUserService().getSecretQuestion(user));
    }

    @Override
    public String getChallengeUrl(AuthenticationSession session) {
        return loginPage;
    }

    @Override
    public AuthenticationCredentials getCredentials(AuthenticationSession session) {
        AuthenticationCredentials credentials = session.getUserLogin().getUnvalidatedCredentials(getSchemeId());
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
    public Authenticated authenticate(AuthenticationCredentials credentials, UserLogin userLogin) {

        // Ensure the credentials provided are of the expected type
        if (!(credentials instanceof SecretQuestionAuthenticationCredentials)) {
            throw new ContextAuthenticationException("authentication.error.incorrectCredentialsForScheme");
        }
        SecretQuestionAuthenticationCredentials c = (SecretQuestionAuthenticationCredentials) credentials;

        if (c.user == null) {
            throw new ContextAuthenticationException("authentication.error.candidateUserRequired");
        }
        if (StringUtils.isBlank(c.question) || StringUtils.isBlank(c.answer)) {
            throw new ContextAuthenticationException("authentication.error.noSecretQuestionConfigured");
        }
        if (userLogin.getUser() != null && !userLogin.getUser().equals(c.user)) {
            throw new ContextAuthenticationException("authentication.error.userDiffersFromCandidateUser");
        }
        String expectedQuestion = getSecretQuestion(c.user);
        if (StringUtils.isBlank(expectedQuestion) || !expectedQuestion.equalsIgnoreCase(c.question)) {
            throw new ContextAuthenticationException("authentication.error.incorrectQuestion");
        }
        if (!isSecretAnswer(c.user, c.answer)) {
            throw new ContextAuthenticationException("authentication.error.incorrectAnswer");
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
            return getSchemeId();
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
