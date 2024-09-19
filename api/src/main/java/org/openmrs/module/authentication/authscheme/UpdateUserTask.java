package org.openmrs.module.authentication.authscheme;

import org.apache.commons.beanutils.BeanUtilsBean;
import org.openmrs.User;
import org.openmrs.api.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.util.ClassUtils;

import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.stream.Collectors;

public class UpdateUserTask implements Runnable {
	
	private final static Logger log = LoggerFactory.getLogger(UpdateUserTask.class);
	
	private UserService userService;
	
	private UserInfo userInfo;
	
	public UpdateUserTask(UserService userService, UserInfo userInfo) {
		this.userService = userService;
		this.userInfo = userInfo;
	}
	
	@Override
	public void run() {
		User user = userService.getUserByUsername(userInfo.getUsername());
		userService.saveUser(updated(user));
	}
	
	/**
	 * A bean utils bean to copy over non-null values from a bean to another. Nested non-primitive
	 * types are handled recursively.
	 * 
	 * @see https://stackoverflow.com/a/3521314/321797
	 */
	static class NullAwareBeanUtilsBean extends BeanUtilsBean {
		
		private boolean isPrimitiveType(Object obj) {
			return ClassUtils.isPrimitiveOrWrapper(obj.getClass()) || obj instanceof String;
		}
		
		private void copyCollection(Collection<?> dest, Collection<?> value) throws IllegalAccessException,
		        InvocationTargetException {
			if (dest.size() > 1 || value.size() > 1) {
				// TODO: log an appropriate error, or even throw
				return;
			}
			
			Object d = dest.stream().findFirst().orElse(null);
			Object v = value.stream().findFirst().orElse(null);
			
			if (v == null) {
				dest.clear();
			} else if (isPrimitiveType(v) || d == null) {
				dest = value;
			} else {
				new NullAwareBeanUtilsBean().copyProperties(d, v);
			}
		}
		
		@Override
		public void copyProperty(Object dest, String name, Object value) throws IllegalAccessException,
		        InvocationTargetException {
			if (value == null) {
				return;
			}
			
			Object destPropertyValue = new BeanWrapperImpl(dest).getPropertyValue(name);
			if (value.equals(destPropertyValue)) {
				return;
			}
			
			if (isPrimitiveType(value) || destPropertyValue == null) {
				super.copyProperty(dest, name, value);
			} else if (Collection.class.isAssignableFrom(destPropertyValue.getClass())) {
				copyCollection((Collection<?>) destPropertyValue, (Collection<?>) value);
			} else if (destPropertyValue.getClass().isArray()) {
				// TODO: handle arrays
			} else {
				new NullAwareBeanUtilsBean().copyProperties(destPropertyValue, value);
			}
		}
	}
	
	/**
	 * Returns the updated user as per the user info.
	 * 
	 * @param user The user to update
	 * @return The updated user.
	 */
	private User updated(User user) {
		
		try {
			User openmrsUser = userInfo.getOpenmrsUser();
			// UUIDs should be stable
			if (user.getUuid() != null) {
				openmrsUser.setUuid(user.getUuid());
			}
			
			if (user.getPerson() != null && user.getPerson().getUuid() != null) {
				openmrsUser.getPerson().setUuid(user.getPerson().getUuid());
			}
			
			if (user.getPerson() != null && user.getPerson().getPersonName() != null && user.getPerson().getPersonName().getUuid() != null) {
				openmrsUser.getPerson().getPersonName().setUuid(user.getPerson().getPersonName().getUuid());
			}
			
			new NullAwareBeanUtilsBean().copyProperties(user, openmrsUser);
		}
		catch (IllegalAccessException | InvocationTargetException e) {
			log.error("Something went wrong when copying attributes from the user info to the OpenMRS user, the OpenMRS user might not have been updated properly.", e);
		}
		
		if (userInfo.getRoleNames() != null) {
			user.setRoles(userInfo.getRoleNames().stream().map(roleName -> userService.getRole(roleName)).filter(r -> r != null).collect(Collectors.toSet()));
		}
		
		return user;
	}
}
