/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.mocks;

import org.openmrs.User;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.module.authentication.web.EmailAuthenticationScheme;

import java.util.HashMap;
import java.util.Map;

/**
 * Mock implementation of EmailAuthenticationScheme for testing, which avoids live Context calls
 * by overriding email lookup and send operations.
 */
public class MockEmailAuthenticationScheme extends EmailAuthenticationScheme {

	private final Map<String, String> userEmails = new HashMap<>();
	private String lastSentEmail;
	private String lastSentCode;

	public MockEmailAuthenticationScheme() {
	}

	public void setUserEmail(String username, String email) {
		userEmails.put(username, email);
	}

	public String getLastSentEmail() {
		return lastSentEmail;
	}

	public String getLastSentCode() {
		return lastSentCode;
	}

	@Override
	protected String getUserEmail(User user) {
		String email = userEmails.get(user.getUsername());
		if (email == null) {
			throw new ContextAuthenticationException("authentication.error.noEmailConfiguredForUser");
		}
		return email;
	}

	@Override
	protected void sendCode(User user, String code) {
		lastSentEmail = getUserEmail(user);
		lastSentCode = code;
	}
}
