package org.openmrs.module.authentication.authscheme;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.List;
import java.util.Properties;

import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.openmrs.module.authentication.authscheme.UserInfo.PROP_ROLES;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore("javax.management.*")
public class UserInfoTest{
	
	private UserInfo userInfo;
	
	private Properties oauth2Props = new Properties();
	
	@Test
	public void getRoleNames_shouldParseAndTrimRoleNamesWhenMappingIsDefined() throws Exception {
		// setup
		oauth2Props.setProperty(PROP_ROLES, "roles");
		userInfo = new UserInfo(oauth2Props, "{\"roles\": [\"Nurse\", \"Doctor\"]}");
		
		// replay
		List<String> roleNames = userInfo.getRoleNames();
		
		// verify
		Assert.assertThat(roleNames, hasSize(2));
		Assert.assertThat(roleNames, containsInAnyOrder("Nurse", "Doctor"));
	}
	
	@Test
	public void getRoleNames_shouldParseToNullWhenMappingIsNotDefined() {
		// setup
		oauth2Props = new Properties();
		userInfo = new UserInfo(oauth2Props, "{\"roles\": [\"Nurse\", \"Doctor\"]}");
		
		// replay
		List<String> roleNames = userInfo.getRoleNames();
		
		// verify
		Assert.assertNull(roleNames);
	}
	
	@Test
	public void getRoleNames_shouldParseToEmptyRoleNamesWhenNoneInUserInfo() {
		// setup
		oauth2Props.setProperty(PROP_ROLES, "roles");
		userInfo = new UserInfo(oauth2Props, "{}");
		
		// replay
		List<String> roleNames = userInfo.getRoleNames();
		
		// verify
		Assert.assertThat(roleNames, empty());
	}
}
