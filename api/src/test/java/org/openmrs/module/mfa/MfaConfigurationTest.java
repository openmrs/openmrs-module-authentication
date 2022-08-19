package org.openmrs.module.mfa;

import org.junit.Test;
import org.openmrs.test.BaseModuleContextSensitiveTest;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.openmrs.module.mfa.MfaConfiguration.CONFIGURATION_CACHE_ENABLED;
import static org.openmrs.module.mfa.MfaConfiguration.FILTER_UNAUTHENTICATED_URLS;

public class MfaConfigurationTest extends BaseModuleContextSensitiveTest {
	
	@Autowired
	MfaConfiguration mfaConfiguration;
	
	@Test
	public void shouldLoadMfaConfigurationAsBean() {
		assertThat(mfaConfiguration, notNullValue());
	}

	@Test
	public void shouldGetBooleanProperty() {
		Properties p = new Properties();
		p.setProperty(CONFIGURATION_CACHE_ENABLED, "false");
		mfaConfiguration.setConfigurationCache(p);
		assertThat(mfaConfiguration.getBoolean(CONFIGURATION_CACHE_ENABLED, true), equalTo(false));
		p.setProperty(CONFIGURATION_CACHE_ENABLED, "true");
		mfaConfiguration.setConfigurationCache(p);
		assertThat(mfaConfiguration.getBoolean(CONFIGURATION_CACHE_ENABLED, false), equalTo(true));
	}

	@Test
	public void shouldGetStringListProperty() {
		Properties p = new Properties();
		assertThat(mfaConfiguration.getStringList(FILTER_UNAUTHENTICATED_URLS).size(), equalTo(0));
		p.setProperty(FILTER_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg,*.png");
		mfaConfiguration.setConfigurationCache(p);
		List<String> urls = mfaConfiguration.getStringList(FILTER_UNAUTHENTICATED_URLS);
		assertThat(urls.size(), equalTo(4));
		assertThat(urls.get(0), equalTo("*.css"));
		assertThat(urls.get(1), equalTo("*.gif"));
		assertThat(urls.get(2), equalTo("*.jpg"));
		assertThat(urls.get(3), equalTo("*.png"));
	}
}
