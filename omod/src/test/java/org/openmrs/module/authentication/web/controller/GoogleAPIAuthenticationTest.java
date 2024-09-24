/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.controller;

import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.openmrs.User;
import org.openmrs.api.PatientService;
import org.openmrs.api.context.Context;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.springframework.beans.factory.annotation.Autowired;

@PrepareForTest(Context.class)
public class GoogleAPIAuthenticationTest extends OAuth2IntegrationTest {

	@Autowired
	private PatientService patientService;
	@Override
	protected String getAppDataDirName() {
		return "GoogleAPI";
	}

	@BeforeEach
	public void setup() throws Exception {
		patientService.getPatients("");
	}
	@Override
	protected String getUserInfoJson() {
		return "{\n" + "  \"sub\": \"31a709c3-67f4-4b01-b76c-b39e650c0a41\",\n" + "  \"name\": \"John Doe\",\n"
		        + "  \"given_name\": \"John\",\n" + "  \"family_name\": \"Doe\",\n"
		        + "  \"profile\": \"http://example.com/profile\",\n" + "  \"picture\": \"http://example.com/picture\",\n"
		        + "  \"email\": \"jdoe@example.com\",\n" + "  \"email_verified\": true,\n" + "  \"locale\": \"en\",\n" + "}";
	}
	
	@Override
	protected void assertAuthenticatedUser(User user) {
		Assert.assertEquals("31a709c3-67f4-4b01-b76c-b39e650c0a41", user.getUsername());
		Assert.assertEquals("31a709c3-67f4-4b01-b76c-b39e650c0a41", user.getSystemId());
		Assert.assertEquals("John", user.getGivenName());
		Assert.assertEquals("Doe", user.getFamilyName());
		Assert.assertEquals("jdoe@example.com", user.getEmail());
		assertThatProviderAccountIsActivated(user);
	}
	
	@Override
	protected String[] roleNamesToAssert() {
		return new String[] {};
	}
	
}
