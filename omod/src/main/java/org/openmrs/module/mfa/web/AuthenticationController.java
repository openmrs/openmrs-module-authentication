/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.mfa.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class AuthenticationController {
	
	protected final Log log = LogFactory.getLog(getClass());

	@RequestMapping(value = "/module/mfa/basic.htm", method = GET)
	public ModelAndView basicLogin() {
		return new ModelAndView("/module/mfa/basic");
	}

	@RequestMapping(value = "/module/mfa/token.htm", method = GET)
	public ModelAndView tokenChallenge() {
		return new ModelAndView("/module/mfa/token");
	}
}
