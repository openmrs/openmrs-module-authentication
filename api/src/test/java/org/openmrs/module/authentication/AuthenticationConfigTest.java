package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;

import java.util.Date;
import java.util.List;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.openmrs.module.authentication.AuthenticationConfig.SCHEME;
import static org.openmrs.module.authentication.AuthenticationConfig.SETTINGS_CACHED;
import static org.openmrs.module.authentication.AuthenticationConfig.WHITE_LIST;

public class AuthenticationConfigTest extends BaseAuthenticationTest {

	@Test
	public void shouldGetAndSetKeysAndProperties() {
		AuthenticationConfig.setConfig(new Properties());
		AuthenticationConfig.setProperty("testBoolean", "false");
		AuthenticationConfig.setProperty(WHITE_LIST, "*.css");
		assertThat(AuthenticationConfig.getKeys().size(), equalTo(2));
		assertThat(AuthenticationConfig.getProperty("testBoolean"), equalTo("false"));
		assertThat(AuthenticationConfig.getProperty(WHITE_LIST), equalTo("*.css"));
		assertThat(AuthenticationConfig.getProperty(SETTINGS_CACHED), nullValue());
		assertThat(AuthenticationConfig.getProperty(SETTINGS_CACHED, "true"), equalTo("true"));
		assertThat(AuthenticationConfig.getKeys().contains("testBoolean"), equalTo(true));
		assertThat(AuthenticationConfig.getKeys().contains(WHITE_LIST), equalTo(true));
		assertThat(AuthenticationConfig.getKeys().contains(SETTINGS_CACHED), equalTo(false));
	}

	@Test
	public void shouldGetBooleanProperty() {
		AuthenticationConfig.setProperty("testBoolean", "false");
		assertThat(AuthenticationConfig.getBoolean("testBoolean", true), equalTo(false));
		AuthenticationConfig.setProperty("testBoolean", "true");
		assertThat(AuthenticationConfig.getBoolean("testBoolean", false), equalTo(true));
	}

	@Test
	public void shouldGetStringListProperty() {
		String propertyName = "testStringList";
		assertThat(AuthenticationConfig.getStringList(propertyName).size(), equalTo(0));
		AuthenticationConfig.setProperty(propertyName, "*.css,*.gif,*.jpg,*.png");
		List<String> urls = AuthenticationConfig.getStringList(propertyName);
		assertThat(urls.size(), equalTo(4));
		assertThat(urls.get(0), equalTo("*.css"));
		assertThat(urls.get(1), equalTo("*.gif"));
		assertThat(urls.get(2), equalTo("*.jpg"));
		assertThat(urls.get(3), equalTo("*.png"));
	}

	@Test
	public void shouldGetClassInstance() {
		AuthenticationConfig.setProperty("user", "org.openmrs.User");
		User user = AuthenticationConfig.getClassInstance("user", User.class);
		assertThat(user, notNullValue());
		assertThat(user.getClass(), equalTo(User.class));
	}

	@Test
	public void shouldGetClass() {
		AuthenticationConfig.setProperty("date", "java.util.Date");
		Class<?> userClass = AuthenticationConfig.getClass("date", Date.class);
		assertThat(userClass, notNullValue());
		assertThat(userClass, equalTo(Date.class));
	}

	@Test
	public void shouldGetPropertiesWithPrefix() {
		AuthenticationConfig.setProperty("prefs.color", "red");
		AuthenticationConfig.setProperty("prefs.season", "fall");
		AuthenticationConfig.setProperty("prefs.timeOfDay", "morning");
		AuthenticationConfig.setProperty("preferences.prefs.timeOfDay", "evening");
		{
			Properties p = AuthenticationConfig.getSubsetWithPrefix("prefs.", true);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), nullValue());
			assertThat(p.getProperty("prefs.season"), nullValue());
			assertThat(p.getProperty("prefs.timeOfDay"), nullValue());
			assertThat(p.getProperty("color"), equalTo("red"));
			assertThat(p.getProperty("season"), equalTo("fall"));
			assertThat(p.getProperty("timeOfDay"), equalTo("morning"));
		}
		{
			Properties p = AuthenticationConfig.getSubsetWithPrefix("prefs.", false);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), equalTo("red"));
			assertThat(p.getProperty("prefs.season"), equalTo("fall"));
			assertThat(p.getProperty("prefs.timeOfDay"), equalTo("morning"));
			assertThat(p.getProperty("color"), nullValue());
			assertThat(p.getProperty("season"), nullValue());
			assertThat(p.getProperty("timeOfDay"), nullValue());
		}
	}

	@Test
	public void shouldGetConfigurationCacheEnabled() {
		AuthenticationConfig.setProperty(SETTINGS_CACHED, "false");
		assertThat(AuthenticationConfig.isConfigurationCacheEnabled(), equalTo(false));
		AuthenticationConfig.setProperty(SETTINGS_CACHED, "true");
		assertThat(AuthenticationConfig.isConfigurationCacheEnabled(), equalTo(true));
	}

	@Test
	public void shouldGetWhiteList() {
		AuthenticationConfig.setProperty(WHITE_LIST, "*.pdf");
		List<String> patterns = AuthenticationConfig.getWhiteList();
		assertThat(patterns.size(), equalTo(19));
		assertThat(patterns.contains("*.pdf"), equalTo(true));
	}

	@Test
	public void shouldGetAuthenticationScheme() {
		AuthenticationConfig.setProperty("authentication.scheme.test.type", "org.openmrs.module.authentication.TestAuthenticationScheme");
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(UsernamePasswordAuthenticationScheme.class));
		AuthenticationConfig.setProperty(SCHEME, "test");
		scheme = AuthenticationConfig.getAuthenticationScheme();
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(TestAuthenticationScheme.class));
	}

	@Test
	public void shouldGetAuthenticationSchemeById() {
		AuthenticationConfig.setProperty("authentication.scheme.test1.type", "org.openmrs.module.authentication.TestAuthenticationScheme");
		AuthenticationConfig.setProperty("authentication.scheme.test2.type", "org.openmrs.module.authentication.TestAuthenticationScheme");
		AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme("test1");
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(TestAuthenticationScheme.class));
		assertThat(((TestAuthenticationScheme)scheme).getSchemeId(), equalTo("test1"));
		scheme = AuthenticationConfig.getAuthenticationScheme("test2");
		assertThat(scheme, notNullValue());
		assertThat(scheme.getClass(), equalTo(TestAuthenticationScheme.class));
		assertThat(((TestAuthenticationScheme)scheme).getSchemeId(), equalTo("test2"));
	}
}
