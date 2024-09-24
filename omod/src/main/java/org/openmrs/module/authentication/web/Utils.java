package org.openmrs.module.authentication.web;

import org.openmrs.util.OpenmrsUtil;

import java.io.File;
import java.nio.file.Paths;

/**
 * Contains general utility methods
 */
public class Utils {
	
	/**
	 * Gets a file located in the OpenMRS app data directory
	 * 
	 * @param filename the name of the file to lookup
	 * @return The file object
	 * @throws Exception
	 */
	public static File getFileInAppDataDirectory(String filename) {
		return Paths.get(OpenmrsUtil.getApplicationDataDirectory(), filename).toFile();
	}
	
}
