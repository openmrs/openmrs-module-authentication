package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.UserSessionListener;

public class AuthenticationUserSessionListenerTest extends BaseAuthenticationTest {

	@Test
	public void shouldLogAtLoggedInOrOut() {
		User user = new User();
		user.setUserId(1234);
		user.setUsername("testing");
		AuthenticationUserSessionListener listener = new AuthenticationUserSessionListener();
		listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.SUCCESS);
		assertLastLogContains("marker=AUTHENTICATION_LOGIN_SUCCEEDED,message=user=testing");
		listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.FAIL);
		assertLastLogContains("marker=AUTHENTICATION_LOGIN_FAILED,message=user=testing");
		listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.SUCCESS);
		assertLastLogContains("marker=AUTHENTICATION_LOGOUT_SUCCEEDED,message=user=testing");
		listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.FAIL);
		assertLastLogContains("marker=AUTHENTICATION_LOGOUT_FAILED,message=user=testing");
	}
}
