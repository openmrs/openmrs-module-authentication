package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.UserSessionListener;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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
		UserLogin login = new UserLogin();
		login.setUser(user);
		try {
			UserLoginTracker.setLoginOnThread(login);
			AuthenticationUserSessionListener listener = new AuthenticationUserSessionListener();
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.SUCCESS);
			assertLoggedEvent(login, LOGIN_SUCCEEDED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGIN, UserSessionListener.Status.FAIL);
			assertLoggedEvent(login, LOGIN_FAILED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.SUCCESS);
			assertLoggedEvent(login, LOGOUT_SUCCEEDED);
			listener.loggedInOrOut(user, UserSessionListener.Event.LOGOUT, UserSessionListener.Status.FAIL);
			assertLoggedEvent(login, LOGOUT_FAILED);
		}
		finally {
			UserLoginTracker.removeLoginFromThread();
		}
	}

	protected void assertLoggedEvent(UserLogin userLogin, String event) {
		assertThat(userLogin.containsEvent(event), equalTo(true));
		assertLastLogContains("event=" + event);
		assertLastLogContains("loginId=" + userLogin.getLoginId());
		assertLastLogContains("userId=" + userLogin.getUserId());
		assertLastLogContains("username=" + userLogin.getUsername());
	}
}
