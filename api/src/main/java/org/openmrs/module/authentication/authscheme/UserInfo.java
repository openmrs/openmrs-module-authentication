/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.authscheme;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import  net.minidev.json.JSONArray;
import org.openmrs.Person;
import org.openmrs.PersonName;
import org.openmrs.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * This is an object representation of the OAuth2 user info response with convenience methods to
 * extract useful information from it.
 */
public class UserInfo {
	
	private final static Logger log = LoggerFactory.getLogger(UserInfo.class);
	
	public final static String MAPPINGS_PFX = "openmrs.mapping.";
	
	public final static String PROP_USERNAME = MAPPINGS_PFX + "user.username";
	
	public final static String PROP_USERNAME_SERVICE_ACCOUNT = MAPPINGS_PFX + "user.username.serviceAccount";
	
	public final static String PROP_EMAIL = MAPPINGS_PFX + "user.email";
	
	public final static String PROP_GIVEN_NAME = MAPPINGS_PFX + "person.givenName";
	
	public final static String PROP_MIDDLE_NAME = MAPPINGS_PFX + "person.middleName";
	
	public final static String PROP_FAMILY_NAME = MAPPINGS_PFX + "person.familyName";
	
	public final static String PROP_GENDER = MAPPINGS_PFX + "person.gender";
	
	public final static String PROP_SYSTEMID = MAPPINGS_PFX + "user.systemId";
	
	public static final String PROP_ROLES = MAPPINGS_PFX + "user.roles";
	
	public final static String PROP_PROVIDER = MAPPINGS_PFX + "user.provider";
	
	private String json; // the user info json
	
	private Properties props;
	
	/**
	 * The user info object representation is built from the user info JSON and the OAuth2 mapping
	 * properties file. The OAuth2 properties file defines the mappings between OpenMRS meaningful
	 * values (such as 'username', 'user/person first name', 'user email', 'user/person gender' ...
	 * etc, and the root level keys where they are found in the user info JSON.
	 * 
	 * @param oauth2Props A mapping between OpenMRS' user or person values and the fields where they
	 *            are to be found in the user info JSON.
	 * @param userInfoJson The user info JSON.
	 */
	public UserInfo(Properties oauth2Props, String userInfoJson) {
		this.props = oauth2Props;
		this.json = userInfoJson;
	}
	
	@Override
	public String toString() {
		return getUsername();
	}
	
	/**
	 * Fetches the value in the user info JSON based on the property key as defined in the OAuth2
	 * properties file. To do so, this methods maps a property key to a user info JSON key, before
	 * fetching the corresponding value in the user info JSON. Eg.: "openmrs.mapping.user.username"
	 * → "username" → "jdoe".
	 * 
	 * @throws RuntimeException as a general matter of fact, see below.
	 * @throws IllegalArgumentException when the requested property key is not documented in the
	 *             OAuth2 properties mapping file.
	 * @throws PathNotFoundException when the mapped JSON key cannot be located in the user info
	 *             JSON.
	 * @param propertyKey The OpenMRS property whose value is to be fetched out of the user info
	 *            JSON, eg. "openmrs.mapping.user.username".
	 * @return The user info JSON value for the specified OpenMRS property key.
	 */
	public Object get(String propertyKey) throws RuntimeException {
		if (props.containsKey(propertyKey)) {
			String jsonKey = props.getProperty(propertyKey);
			try {
				return JsonPath.read(json, "$." + jsonKey);
			}
			catch (PathNotFoundException e) {
				throw new PathNotFoundException("There was an error when reading the JSON path $." + jsonKey
				        + " mapped from '" + propertyKey + "' in the user info JSON.", e);
			}
		}
		return null;
	}
	
	/**
	 * Fetches the value in the user info JSON as a String based on the property key as defined in
	 * the OAuth2 properties file. If the key is not defined in the OAuth2 properties file or if the
	 * value for that key cannot be parsed from the user info JSON file, then the fallback default
	 * value is returned.
	 * 
	 * @param propertyKey The OpenMRS property whose value is to be fetched out of the user info
	 *            JSON, eg. "openmrs.mapping.user.username".
	 * @param defaultValue The default value.
	 * @return The String user info JSON value for the specified OpenMRS property key.
	 */
	public String getString(String propertyKey, String defaultValue) {
		String res = defaultValue;
		
		Object val = null;
		try {
			val = get(propertyKey);
		}
		catch (RuntimeException e) {
			log.warn(e.getMessage(), e);
			return res;
		}
		if (val == null) {
			return res;
		}
		
		try {
			res = (String) val;
		}
		catch (ClassCastException e) {
			throw new IllegalArgumentException("The user info JSON value corresponding to the key '" + propertyKey
			        + "' cannot be resolved to a simple string value, perhaps is it a structured object?", e);
		}
		
		return res;
	}
	
	/**
	 * @see #getString(String, String)
	 */
	public String getString(String propertyKey) {
		return getString(propertyKey, null);
	}
	
	/**
	 * Convenience method that retrieves the OpenMRS user name from the OAuth2 user info JSON based
	 * on the mappings defined in the OAuth2 properties file.
	 * 
	 * @return The OpenMRS username.
	 */
	public String getUsername() {
		return getString(PROP_USERNAME);
	}
	
	/**
	 * Convenience method to get an OpenMRS {@link User} from the OAuth2 user info JSON based on the
	 * mappings defined in the OAuth2 properties file. This method will not attempt to set any
	 * default values when mappings are not defined in the OAuth2 properties file.
	 * 
	 * @return A minimum viable OpenMRS {@link User}.
	 */
	public User getOpenmrsUser() {
		return getOpenmrsUser(null);
	}
	
	/**
	 * Convenience method to get an OpenMRS {@link User} from the OAuth2 user info JSON based on the
	 * mappings defined in the OAuth2 properties file.
	 * 
	 * @param defaultGender The default gender to apply if it is not mapped in the OAuth2 properties
	 *            file.
	 * @return A minimum viable OpenMRS {@link User}.
	 */
	public User getOpenmrsUser(String defaultGender) {
		
		User user = new User();
		user.setUsername(getUsername());
		user.setSystemId(getString(PROP_SYSTEMID));
		user.setEmail(getString(PROP_EMAIL));
		
		Person person = new Person();
		person.setGender(getString(PROP_GENDER, defaultGender));
		PersonName name = new PersonName();
		name.setGivenName(getString(PROP_GIVEN_NAME));
		name.setMiddleName(getString(PROP_MIDDLE_NAME));
		name.setFamilyName(getString(PROP_FAMILY_NAME));
		
		user.setPerson(person);
		user.addName(name);
		
		return user;
	}
	
	/**
	 * Convenience method that retrieves the list of role names from the OAuth2 user info JSON based
	 * on the mappings defined in the OAuth2 properties file.
	 * 
	 * @return The list of role <i>names</i>, eg. ["Nurse", "Anaesthesia Assistant"].
	 */
	public List<String> getRoleNames() {
		Object val = null;
		try {
			val = get(PROP_ROLES);
			if (val == null) {
				return null;
			}
		}
		catch (RuntimeException e) {
			log.error(e.getMessage(), e);
			return Collections.emptyList();
		}
		
		JSONArray jsonArray = (JSONArray) val;
		return IntStream.range(0, jsonArray.size())
				.mapToObj(i -> (String) jsonArray.get(i))
				.collect(Collectors.toList());

	}
}
