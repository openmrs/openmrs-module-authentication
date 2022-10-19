package org.openmrs.module.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;

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

public class AuthenticationContextTest extends BaseAuthenticationTest {

	@BeforeEach
	public void setup() {
		super.setup();
		AuthenticationConfig.setConfig(new Properties());
		AuthenticationConfig.setProperty("authentication.scheme.test1.type", TestAuthenticationScheme.class.getName());
		AuthenticationConfig.setProperty("authentication.scheme.test2.type", TestAuthenticationScheme.class.getName());
	}

	@Test
	public void shouldSerializeAndDeserialize() throws Exception {
		assertThat(Serializable.class.isAssignableFrom(AuthenticationContext.class), equalTo(true));

		AuthenticationContext ctx = new AuthenticationContext();
		User u = new User();
		u.setUsername("admin");
		ctx.setCandidateUser(u);
		ctx.addCredentials(new TestAuthenticationCredentials("test", u));

		File serializedDataFile = File.createTempFile(getClass().getSimpleName(), "dat");
		serializedDataFile.deleteOnExit();
		FileOutputStream fileOutputStream = new FileOutputStream(serializedDataFile);
		try (ObjectOutputStream out = new ObjectOutputStream(fileOutputStream)) {
			out.writeObject(ctx);
		}
		FileInputStream fileInputStream = new FileInputStream(serializedDataFile);
		try (ObjectInputStream in = new ObjectInputStream(fileInputStream)) {
			AuthenticationContext deserialized = (AuthenticationContext) in.readObject();
			assertThat(deserialized, notNullValue());
			assertThat(deserialized.getCandidateUser(), equalTo(u));
			AuthenticationCredentials credentials = deserialized.getCredentials("test");
			assertThat(credentials, notNullValue());
			assertThat(credentials.getClass(), equalTo(TestAuthenticationCredentials.class));
			TestAuthenticationCredentials testCredentials = (TestAuthenticationCredentials) credentials;
			assertThat(testCredentials.getAuthenticationScheme(), equalTo("test"));
			assertThat(testCredentials.getClientName(), equalTo("admin"));
			assertThat(testCredentials.getUser(), equalTo(u));
		}
	}

	@Test
	public void shouldAddGetAndRemoveCredentials() {
		AuthenticationContext ctx = new AuthenticationContext();
		User user1 = new User();
		user1.setUsername("user1");
		ctx.addCredentials(new TestAuthenticationCredentials("scheme1", user1));
		User user2 = new User();
		user2.setUsername("user2");
		ctx.addCredentials(new TestAuthenticationCredentials("scheme2", user2));
		AuthenticationCredentials c1 = ctx.getCredentials("scheme1");
		assertThat(c1.getAuthenticationScheme(), equalTo("scheme1"));
		assertThat(c1.getClass(), equalTo(TestAuthenticationCredentials.class));
		assertThat(c1.getClientName(), equalTo("user1"));
		AuthenticationCredentials c2 = ctx.getCredentials("scheme2");
		assertThat(c2.getAuthenticationScheme(), equalTo("scheme2"));
		assertThat(c2.getClass(), equalTo(TestAuthenticationCredentials.class));
		assertThat(c2.getClientName(), equalTo("user2"));
		ctx.removeCredentials(c1);
		assertThat(ctx.getCredentials("scheme1"), nullValue());
		ctx.removeCredentials("scheme2");
		assertThat(ctx.getCredentials("scheme2"), nullValue());
	}
}
