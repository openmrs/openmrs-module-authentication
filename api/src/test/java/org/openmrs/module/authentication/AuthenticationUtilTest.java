package org.openmrs.module.authentication;

import org.junit.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link AuthenticationUtil}.
 */
public class AuthenticationUtilTest {

    @Test
    public void getBoolean_shouldReturnDefaultWhenValueIsBlank() {
        assertTrue(AuthenticationUtil.getBoolean(null, true));
        assertFalse(AuthenticationUtil.getBoolean("   ", false));
    }

    @Test
    public void getBoolean_shouldParseNonBlankValues() {
        assertTrue(AuthenticationUtil.getBoolean("true", false));
        assertFalse(AuthenticationUtil.getBoolean("false", true));
    }

    @Test
    public void getInteger_shouldReturnDefaultWhenValueIsBlank() {
        assertEquals(Integer.valueOf(5), AuthenticationUtil.getInteger(null, 5));
        assertEquals(Integer.valueOf(10), AuthenticationUtil.getInteger("   ", 10));
    }

    @Test
    public void getInteger_shouldParseNonBlankValues() {
        assertEquals(Integer.valueOf(123), AuthenticationUtil.getInteger("123", 0));
    }

    @Test
    public void getStringList_shouldReturnEmptyListForBlankValue() {
        List<String> result = AuthenticationUtil.getStringList("   ", ",");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void getStringList_shouldSplitStringByDelimiter() {
        List<String> result = AuthenticationUtil.getStringList("one,two,three", ",");
        assertEquals(Arrays.asList("one", "two", "three"), result);
    }

    @Test
    public void getPropertiesWithPrefix_shouldFilterAndStripPrefixWhenRequested() {
        Properties props = new Properties();
        props.setProperty("auth.key1", "value1");
        props.setProperty("auth.key2", "value2");
        props.setProperty("other.key", "ignored");

        Properties result = AuthenticationUtil.getPropertiesWithPrefix(props, "auth.", true);

        assertEquals(2, result.size());
        assertEquals("value1", result.getProperty("key1"));
        assertEquals("value2", result.getProperty("key2"));
        assertNull(result.getProperty("other.key"));
    }

    @Test
    public void getPropertiesWithPrefix_shouldKeepPrefixWhenNotStripping() {
        Properties props = new Properties();
        props.setProperty("auth.key1", "value1");
        props.setProperty("auth.key2", "value2");

        Properties result = AuthenticationUtil.getPropertiesWithPrefix(props, "auth.", false);

        assertEquals(2, result.size());
        assertEquals("value1", result.getProperty("auth.key1"));
        assertEquals("value2", result.getProperty("auth.key2"));
    }

    @Test
    public void formatIsoDate_shouldReturnNullWhenDateIsNull() {
        assertNull(AuthenticationUtil.formatIsoDate(null));
    }

    @Test
    public void formatIsoDate_shouldFormatDateInIsoPattern() {
        // Use a fixed Date instance so the output is deterministic.
        Date date = new Date(0L); // 1970-01-01T00:00:00.000 UTC (epoch)
        String formatted = AuthenticationUtil.formatIsoDate(date);

        assertNotNull(formatted);
        assertTrue("Expected formatted date to start with 1970-01-01", formatted.startsWith("1970-01-01"));
        assertEquals("Expected length yyyy-MM-dd'T'HH:mm:ss,SSS", 23, formatted.length());
    }
}