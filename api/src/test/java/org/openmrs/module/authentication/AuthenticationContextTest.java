package org.openmrs.module.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.module.authentication.credentials.AuthenticationCredentials;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;
import org.openmrs.module.authentication.credentials.TokenAuthenticationCredentials;

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
		ctx.setCandidateUser(u);
		ctx.addCredentials(new BasicAuthenticationCredentials("basic", "admin", "test"));
		ctx.addCredentials(new TokenAuthenticationCredentials("token", u, "testToken"));

		File serializedDataFile = File.createTempFile(getClass().getSimpleName(), "dat");
		FileOutputStream fileOutputStream = new FileOutputStream(serializedDataFile);
		try (ObjectOutputStream out = new ObjectOutputStream(fileOutputStream)) {
			out.writeObject(ctx);
		}
		FileInputStream fileInputStream = new FileInputStream(serializedDataFile);
		try (ObjectInputStream in = new ObjectInputStream(fileInputStream)) {
			AuthenticationContext deserialized = (AuthenticationContext) in.readObject();
			assertThat(deserialized, notNullValue());
			assertThat(deserialized.getCandidateUser(), equalTo(u));
			AuthenticationCredentials c1 = deserialized.getCredentials("basic");
			assertThat(c1, notNullValue());
			assertThat(c1.getClass(), equalTo(BasicAuthenticationCredentials.class));
			BasicAuthenticationCredentials basic = (BasicAuthenticationCredentials) c1;
			assertThat(basic.getAuthenticationScheme(), equalTo("basic"));
			assertThat(basic.getUsername(), equalTo("admin"));
			assertThat(basic.getPassword(), equalTo("test"));
			AuthenticationCredentials c2 = deserialized.getCredentials("token");
			assertThat(c2, notNullValue());
			assertThat(c2.getClass(), equalTo(TokenAuthenticationCredentials.class));
			TokenAuthenticationCredentials token = (TokenAuthenticationCredentials) c2;
			assertThat(token.getAuthenticationScheme(), equalTo("token"));
			assertThat(token.getCandidateUser(), equalTo(u));
			assertThat(token.getToken(), equalTo("testToken"));
		}
	}

}
