package org.openmrs.module.mfa;

import org.junit.jupiter.api.Test;
import org.openmrs.test.jupiter.BaseModuleContextSensitiveTest;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.openmrs.module.mfa.MfaConfiguration.CONFIGURATION_CACHE_ENABLED;
import static org.openmrs.module.mfa.MfaConfiguration.FILTER_UNAUTHENTICATED_URLS;

public class MfaConfigurationTest extends BaseModuleContextSensitiveTest {
	
	@Autowired
	MfaConfiguration mfaConfiguration;
	
	@Test
	public void shouldLoadMfaConfigurationAsBean() {
		assertNotNull(mfaConfiguration);
	}

	@Test
	public void shouldGetBooleanProperty() {
		Properties p = new Properties();
		p.setProperty(CONFIGURATION_CACHE_ENABLED, "false");
		mfaConfiguration.setConfigurationCache(p);
		assertFalse(mfaConfiguration.getBoolean(CONFIGURATION_CACHE_ENABLED, true));
		p.setProperty(CONFIGURATION_CACHE_ENABLED, "true");
		mfaConfiguration.setConfigurationCache(p);
		assertTrue(mfaConfiguration.getBoolean(CONFIGURATION_CACHE_ENABLED, false));
	}

	@Test
	public void shouldGetStringListProperty() {
		Properties p = new Properties();
		assertEquals(0, mfaConfiguration.getStringList(FILTER_UNAUTHENTICATED_URLS).size());
		p.setProperty(FILTER_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg,*.png");
		mfaConfiguration.setConfigurationCache(p);
		List<String> urls = mfaConfiguration.getStringList(FILTER_UNAUTHENTICATED_URLS);
		assertEquals(4, urls.size());
		assertEquals("*.css", urls.get(0));
		assertEquals("*.gif", urls.get(1));
		assertEquals("*.jpg", urls.get(2));
		assertEquals("*.png", urls.get(3));
	}
}
