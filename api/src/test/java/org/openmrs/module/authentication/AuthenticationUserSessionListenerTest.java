package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.UserSessionListener;

import static org.openmrs.module.authentication.AuthenticationEvent.LOGIN_FAILED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGIN_SUCCEEDED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGOUT_FAILED;
import static org.openmrs.module.authentication.AuthenticationEvent.LOGOUT_SUCCEEDED;

public class AuthenticationUserSessionListenerTest extends BaseAuthenticationTest {

	@Test
	public void shouldLogAtLoggedInOrOut() throws Exception {
		User user = new User();
		user.setUserId(12345);
		user.setUsername("testing");
		AuthenticationContext context = new AuthenticationContext();
		context.setUser(user);
		try {
			AuthenticationEventLog.contextInitialized(context);
			AuthenticationUserSessionListener listener = new AuthenticationUserSessionListener();
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.SUCCESS);
			assertLoggedEvent(context, LOGIN_SUCCEEDED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.FAIL);
			assertLoggedEvent(context, LOGIN_FAILED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.SUCCESS);
			assertLoggedEvent(context, LOGOUT_SUCCEEDED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.FAIL);
			assertLoggedEvent(context, LOGOUT_FAILED);
		}
		finally {
			AuthenticationEventLog.contextDestroyed(context);
		}
	}

	protected void assertLoggedEvent(AuthenticationContext context, AuthenticationEvent event) {
		assertLastLogContains("event=" + event.name());
		assertLastLogContains("contextId=" + context.getContextId());
		assertLastLogContains("userId=" + context.getUserId());
		assertLastLogContains("username=" + context.getUsername());
	}
}
