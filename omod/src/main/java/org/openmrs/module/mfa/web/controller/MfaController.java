/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web.controller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class MfaController {
	
	protected final Log log = LogFactory.getLog(getClass());

	public static final String DEFAULT_LOGIN_URL = "/login.htm";
	public static final String DEFAULT_LOGIN_SUCCESS_URL = "/index.htm";
	
	@RequestMapping(value = "/module/mfa/primary.htm", method = GET)
	public ModelAndView get(HttpServletRequest request, HttpServletResponse response) throws IOException {


		return new ModelAndView("redirect:" + DEFAULT_LOGIN_SUCCESS_URL);
	}


}
