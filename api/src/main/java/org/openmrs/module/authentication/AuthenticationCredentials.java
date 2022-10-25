/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication;

import org.openmrs.api.context.Credentials;

import java.io.Serializable;

/**
 * Interface for all Credentials supported by Authenticator instances.
 * The primary purpose of this class is to extend Credentials by marking them as Serializable
 */
public interface AuthenticationCredentials extends Credentials, Serializable {

}
