package org.openmrs.module.authentication.authscheme;

import org.junit.Assert;
import org.junit.Test;
import org.openmrs.Person;
import org.openmrs.PersonName;
import org.openmrs.User;
import org.openmrs.module.authentication.authscheme.UpdateUserTask.NullAwareBeanUtilsBean;

public class NullAwareBeanUtilsBeanTest {
	
	@Test
	public void copyProperties_shouldCopyOnlyNonNullProperties() throws Exception {
		
		// setup
		User orig = new User();
		orig.setEmail(null);
		{
			Person p = new Person();
			p.setGender(null);
			p.setCauseOfDeathNonCoded("Cardiac arrest");
			p.addName(new PersonName("Jean", "J", "Doe"));
			orig.setPerson(p);
		}
		
		User dest = new User();
		dest.setEmail("psmith@acme.com");
		{
			Person p = new Person();
			p.setGender("n/a");
			p.setCauseOfDeathNonCoded(null);
			p.addName(new PersonName("Jane", null, "Doe"));
			dest.setPerson(p);
		}
		
		// replay
		new NullAwareBeanUtilsBean().copyProperties(dest, orig);
		
		// verify
		Assert.assertEquals("psmith@acme.com", dest.getEmail());
		Assert.assertEquals("n/a", dest.getPerson().getGender());
		Assert.assertEquals("Cardiac arrest", dest.getPerson().getCauseOfDeathNonCoded());
		Assert.assertEquals("Jean", dest.getGivenName());
		Assert.assertEquals("J", dest.getPersonName().getMiddleName());
		Assert.assertEquals("Doe", dest.getFamilyName());
	}
}
