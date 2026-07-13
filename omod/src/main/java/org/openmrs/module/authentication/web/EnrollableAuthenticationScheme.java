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

import org.openmrs.module.authentication.EnrollmentException;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Interface for authentication schemes that supports user self enrollment.
 * Any scheme implementing this interface enables users to initiate enrollment and verify
 * their setup credentials before activation.
 */
public interface EnrollableAuthenticationScheme {
	/**
	 * Initiates the enrollment process by generating the required setup data.
	 * For example, a TOTP scheme will generate the secret key and the QR code URI
	 *
	 * @param request the current HTTP request
	 * @return a map containing initiation enrollment details (e.g. secret, QR code)
	 */
	Map<String, Object> initiateEnrollment(HttpServletRequest request);
	
	/**
	 * Verifies the credentials submitted by the user to finalize enrollment.
	 *
	 * @param payload a map containing the verification parameters (e.g., {"code": "123456"})
	 * @param request the current HTTP request
	 * @throws EnrollmentException if validation fails (e.g., expired session or incorrect code)
	 */
	void verifyEnrollment(Map<String, Object> payload, HttpServletRequest request);
}
