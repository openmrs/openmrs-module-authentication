package org.openmrs.module.mfa;

import org.junit.Test;

public class MfaLoggerTest {

	@Test
	public void shouldConfigureLoggerAndAppender() {
		MfaLogger.addToContext("sessionId", "AAAAAAAAAAAAAAAAAAAAAAA");
		MfaLogger.logEvent(MfaLogger.Event.LOGIN_SUCCEEDED);
		MfaLogger.logEvent(MfaLogger.Event.PRIMARY_AUTH_FAILED, "test message");
		MfaLogger.clearContext();
	}
}
