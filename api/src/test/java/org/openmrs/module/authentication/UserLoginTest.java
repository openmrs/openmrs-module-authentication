package org.openmrs.module.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.BasicAuthenticated;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class UserLoginTest extends BaseAuthenticationTest {

	@BeforeEach
	public void setup() {
		super.setup();
		AuthenticationConfig.setConfig(new Properties());
		AuthenticationConfig.setProperty("authentication.scheme.test1.type", TestAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.test2.type", TestAuthenticationScheme.class.getName());
	}

	protected User newUser(String username) {
		User user = new User();
		user.setUsername(username);
		return user;
	}

	@Test
	public void shouldSerializeAndDeserialize() throws Exception {
		assertThat(Serializable.class.isAssignableFrom(UserLogin.class), equalTo(true));

		UserLogin ctx = new UserLogin();
		User u = newUser("admin");
		ctx.addUnvalidatedCredentials(new TestAuthenticationCredentials("test1", u));
		ctx.authenticationSuccessful("test1", new BasicAuthenticated(u, "test1"));
		ctx.addUnvalidatedCredentials(new TestAuthenticationCredentials("test2", u));

		File serializedDataFile = File.createTempFile(getClass().getSimpleName(), "dat");
		serializedDataFile.deleteOnExit();
		FileOutputStream fileOutputStream = new FileOutputStream(serializedDataFile);
		try (ObjectOutputStream out = new ObjectOutputStream(fileOutputStream)) {
			out.writeObject(ctx);
		}
		FileInputStream fileInputStream = new FileInputStream(serializedDataFile);
		try (ObjectInputStream in = new ObjectInputStream(fileInputStream)) {
			UserLogin deserialized = (UserLogin) in.readObject();
			assertThat(deserialized, notNullValue());
			assertThat(deserialized.getUser(), equalTo(u));
			AuthenticationCredentials test1 = deserialized.getUnvalidatedCredentials("test1");
			assertThat(test1, nullValue());
			assertThat(deserialized.isCredentialValidated("test1"), equalTo(true));
			AuthenticationCredentials test2 = deserialized.getUnvalidatedCredentials("test2");
			assertThat(test2, notNullValue());
			assertThat(deserialized.isCredentialValidated("test2"), equalTo(false));
			assertThat(test2.getClass(), equalTo(TestAuthenticationCredentials.class));
			TestAuthenticationCredentials testCredentials = (TestAuthenticationCredentials) test2;
			assertThat(testCredentials.getAuthenticationScheme(), equalTo("test2"));
			assertThat(testCredentials.getClientName(), equalTo("admin"));
			assertThat(testCredentials.getUser(), equalTo(u));
		}
	}

	@Test
	public void shouldAddGetAndRemoveCredentials() {
		UserLogin ctx = new UserLogin();
		User user1 = newUser("user1");
		ctx.addUnvalidatedCredentials(new TestAuthenticationCredentials("scheme1", user1));
		User user2 = newUser("user2");
		ctx.addUnvalidatedCredentials(new TestAuthenticationCredentials("scheme2", user2));
		AuthenticationCredentials c1 = ctx.getUnvalidatedCredentials("scheme1");
		assertThat(c1.getAuthenticationScheme(), equalTo("scheme1"));
		assertThat(c1.getClass(), equalTo(TestAuthenticationCredentials.class));
		assertThat(c1.getClientName(), equalTo("user1"));
		AuthenticationCredentials c2 = ctx.getUnvalidatedCredentials("scheme2");
		assertThat(c2.getAuthenticationScheme(), equalTo("scheme2"));
		assertThat(c2.getClass(), equalTo(TestAuthenticationCredentials.class));
		assertThat(c2.getClientName(), equalTo("user2"));
		ctx.authenticationFailed(c1.getAuthenticationScheme());
		assertThat(ctx.getUnvalidatedCredentials("scheme1"), nullValue());
	}
}
