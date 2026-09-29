/**
 * The contents of this file are subject to the OpenMRS Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://license.openmrs.org
 * <p>
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 * <p>
 * Copyright (C) OpenMRS, LLC.  All Rights Reserved.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.lang.StringUtils;
import org.openmrs.Location;
import org.openmrs.LocationTag;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.util.OpenmrsConstants;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.openmrs.module.authentication.AuthenticationUtil.getBoolean;

/**
 * This expands on the BasicWebAuthenticationScheme to also handle collecting, validating, and setting sessionLocation
 */
public class BasicWithLocationAuthenticationScheme extends BasicWebAuthenticationScheme {

	public static final String LOCATION_PARAM_NAME = "locationParamName";
	public static final String ONLY_LOCATIONS_WITH_TAG = "onlyLocationsWithTag";
	public static final String LOCATION_REQUIRED = "locationRequired";
	public static final String LOCATION_SESSION_ATTRIBUTE_NAME = "locationSessionAttributeName";
	public static final String LAST_LOCATION_COOKIE_NAME = "lastLocationCookieName";
	public static final String USE_DEFAULT_LOCATION = "loginUsingDefaultLocationIfSpecified";
	public static final String DEFAULT_LOCATION_ATTRIBUTE_NAME = "defaultLocationAttributeName";

	private String locationParamName = "sessionLocation";
	private String onlyLocationsWithTag = null;
	private boolean locationRequired = false;
	private String locationSessionAttributeName = "emrContext.sessionLocationId";
	private String lastLocationCookieName = "emr.lastSessionLocation";
	private boolean useDefaultLocation = false;
	private String defaultLocationAttributeName = OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCATION;

	@Override
	public void configure(String schemeId, Properties config) {
		super.configure(schemeId, config);
		locationParamName = config.getProperty(LOCATION_PARAM_NAME, "sessionLocation");
		onlyLocationsWithTag = config.getProperty(ONLY_LOCATIONS_WITH_TAG);
		locationRequired = getBoolean(config.getProperty(LOCATION_REQUIRED), false);
		locationSessionAttributeName = config.getProperty(LOCATION_SESSION_ATTRIBUTE_NAME, "emrContext.sessionLocationId");
		lastLocationCookieName = config.getProperty(LAST_LOCATION_COOKIE_NAME, "emr.lastSessionLocation");
		useDefaultLocation = getBoolean(config.getProperty(USE_DEFAULT_LOCATION), false);
		defaultLocationAttributeName = config.getProperty(DEFAULT_LOCATION_ATTRIBUTE_NAME, OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCATION);
	}

	@Override
	public void beforeAuthentication(AuthenticationSession session) {
		super.beforeAuthentication(session);
		Location loginLocation = getLoginLocation(session.getHttpRequest());
		if (loginLocation == null && locationRequired) {
			// TODO: Currently do not support setting session location for authentication via header (REST/FHIR/etc)
			if (session.getRequestHeader(AUTHORIZATION_HEADER) == null) {
				throw new ContextAuthenticationException("authentication.error.locationRequired");
			}
		}
	}

	@Override
	public void afterAuthenticationSuccess(AuthenticationSession session) {
		super.afterAuthenticationSuccess(session);
		Location loginLocation = getLoginLocation(session.getHttpRequest());
		if (loginLocation == null && useDefaultLocation) {
			loginLocation = getDefaultLoginLocation(session.getUserLogin().getUser());
		}
		if (loginLocation != null) {
			Context.getUserContext().setLocation(loginLocation);
			if (StringUtils.isNotBlank(locationSessionAttributeName)) {
				session.setHttpSessionAttribute(locationSessionAttributeName, loginLocation.getLocationId());
			}
			if (StringUtils.isNotBlank(lastLocationCookieName)) {
				session.setCookieValue(lastLocationCookieName, loginLocation.getLocationId().toString());
			}
		}
	}

	/**
	 * @return the Login Location for the given request.  If present in the request, return this location
	 * If not present in the request, but restricting by tags is configured, and only one location with this tag
	 * is set in the system, return the one tagged location
	 */
	protected Location getLoginLocation(HttpServletRequest request) {
		Location loginLocation = null;
		String locationIdStr = request.getParameter(locationParamName);
		if (StringUtils.isNotBlank(locationIdStr)) {
			loginLocation = getLocation(locationIdStr);
			if (loginLocation == null || !isValidLocation(loginLocation)) {
				throw new IllegalArgumentException("authentication.error.invalidLocation");
			}
		}
		if (loginLocation == null) {
			List<Location> validLocations = getValidLocations();
			if (validLocations.size() == 1) {
				loginLocation = validLocations.get(0);
			}
		}
		return loginLocation;
	}

	/**
	 * @return the Location defined as the user's default location if it is a valid login location
	 */
	protected Location getDefaultLoginLocation(User user) {
		Location defaultLocation = getLocation(user.getUserProperty(defaultLocationAttributeName));
		if (defaultLocation != null && isValidLocation(defaultLocation)) {
			return defaultLocation;
		}
		return null;
	}

	/**
	 * @return a Location for the given lookup, first trying to parse to locationId, then trying to lookup by uuid
	 */
	protected Location getLocation(String lookup) {
		Location l = null;
		if (StringUtils.isNotBlank(lookup)) {
			try {
				l = Context.getLocationService().getLocation(Integer.parseInt(lookup));
			} catch (Exception e) {
				l = Context.getLocationService().getLocationByUuid(lookup);
			}
		}
		return l;
	}

	/**
	 * @return a LocationTag for the given lookup, first trying to name, then trying uuid
	 */
	protected LocationTag getLocationTag(String lookup) {
		LocationTag tag = null;
		if (StringUtils.isNotBlank(lookup)) {
			tag = Context.getLocationService().getLocationTagByName(lookup);
			if (tag == null) {
				tag = Context.getLocationService().getLocationTagByUuid(lookup);
			}
		}
		return tag;
	}

	/**
	 * @return a list of all valid locations that could be selected
	 */
	protected List<Location> getValidLocations() {
		List<Location> ret = new ArrayList<>();
		if (StringUtils.isBlank(onlyLocationsWithTag)) {
			ret = Context.getLocationService().getAllLocations();
		}
		else {
			LocationTag locationTag = getLocationTag(onlyLocationsWithTag);
			if (locationTag != null) {
				ret = Context.getLocationService().getLocationsByTag(locationTag);
			}
		}
		return ret;
	}

	/**
	 * @param location the location to check
	 * @return true if the passed location is a valid location to set as the login location
	 */
	protected boolean isValidLocation(Location location) {
		return StringUtils.isBlank(onlyLocationsWithTag) || location.hasTag(onlyLocationsWithTag);
	}
}
