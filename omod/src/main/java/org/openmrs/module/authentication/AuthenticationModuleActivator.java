/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openmrs.module.BaseModuleActivator;
import org.openmrs.module.DaemonToken;
import org.openmrs.module.DaemonTokenAware;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;

/**
 * This class contains the logic that is run every time this module is either started or shutdown
 */
public class AuthenticationModuleActivator extends BaseModuleActivator implements DaemonTokenAware {

	private static final Logger log = LogManager.getLogger(AuthenticationModuleActivator.class);
	
	@Override
	public void started() {
		log.info("Authentication Module Started");
	}
	
	@Override
	public void stopped() {
		log.info("Authentication Module Stopped");
	}

	@Override
	public void setDaemonToken(DaemonToken daemonToken) {
		TwoFactorAuthenticationScheme.setDaemonToken(daemonToken);
	}
}
