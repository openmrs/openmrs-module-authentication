
//Unit tests for {@link UserLoginTracker}.

/**
 * These tests verify both the ThreadLocal tracking of a single UserLogin
 * per thread, and the global collection of active logins.
 */

package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;


public class UserLoginTrackerTest extends BaseAuthenticationTest {

    private UserLogin buildLogin(Integer userId, String loginId) {
        UserLogin login = new UserLogin();
        User user = new User();
        user.setUserId(userId);
        login.setUser(user);
        // loginId is generated in the constructor, but for tracking we rely on getLoginId()
        // in the tracker map; we can't override it, so we just use whatever is generated.
        // We still keep loginId parameter in case in future we want to assert something different.
        return login;
    }

    @Test
    public void setLoginOnThread_shouldAssociateLoginWithCurrentThread() {
        UserLogin login = buildLogin(1, "ignored");

        UserLoginTracker.setLoginOnThread(login);

        UserLogin result = UserLoginTracker.getLoginOnThread();
        assertThat(result, notNullValue());
        assertThat(result.getUser(), notNullValue());
        assertThat(result.getUser().getUserId(), equalTo(1));
    }

    @Test
    public void removeLoginFromThread_shouldClearLoginFromCurrentThread() {
        UserLogin login = buildLogin(1, "ignored");

        UserLoginTracker.setLoginOnThread(login);
        UserLoginTracker.removeLoginFromThread();

        assertThat(UserLoginTracker.getLoginOnThread(), nullValue());
    }

    @Test
    public void addActiveLogin_shouldAddLoginToActiveLoginsMap() {
        UserLogin login = buildLogin(1, "ignored");

        UserLoginTracker.addActiveLogin(login);

        Map<String, UserLogin> active = UserLoginTracker.getActiveLogins();
        assertThat(active.isEmpty(), equalTo(false));
        assertThat(active.values(), hasItem(sameInstance(login)));
    }

    @Test
    public void removeActiveLogin_shouldRemoveLoginFromActiveLoginsMap() {
        UserLogin login = buildLogin(1, "ignored");

        UserLoginTracker.addActiveLogin(login);
        UserLoginTracker.removeActiveLogin(login);

        Map<String, UserLogin> active = UserLoginTracker.getActiveLogins();
        assertThat(active.values(), not(hasItem(sameInstance(login))));
    }

    @Test
    public void getActiveLogins_shouldReturnUnmodifiableMap() {
        UserLogin login = buildLogin(1, "ignored");

        UserLoginTracker.addActiveLogin(login);
        Map<String, UserLogin> active = UserLoginTracker.getActiveLogins();

        assertThat(active.isEmpty(), equalTo(false));

        // The returned map should be unmodifiable
        try {
            active.clear();
            assertThat("Expected getActiveLogins() to return an unmodifiable map", false);
        } catch (UnsupportedOperationException ex) {
            // expected
        }
    }
}