package org.openmrs.module.mfa;

import org.junit.Test;

public class MfaLoggerTest {

	@Test
	public void shouldConfigureLoggerAndAppender() {
		MfaLogger.addToContext("sessionId", "AAAAAAAAAAAAAAAAAAAAAAA");
		MfaLogger.logEvent(MfaLogger.Event.MFA_LOGIN_SUCCEEDED);
		MfaLogger.logEvent(MfaLogger.Event.MFA_PRIMARY_AUTH_FAILED, "test message");
		MfaLogger.clearContext();
	}
}
