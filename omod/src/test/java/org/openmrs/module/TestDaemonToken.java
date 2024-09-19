package org.openmrs.module;

import org.openmrs.module.Module;
import org.openmrs.module.*;

import java.util.stream.Stream;

public class TestDaemonToken {
	
	private class Activator extends BaseModuleActivator implements DaemonTokenAware {
		
		private DaemonToken token;
		
		@Override
		public void setDaemonToken(DaemonToken token) {
			this.token = token;
		}
		
		public DaemonToken getDaemonToken() {
			return token;
		}
		
	}
	
	/**
	 * Sets a valid Daemon token to a collection of {@link DaemonTokenAware} instances so that they
	 * can run Daemon threads in tests.
	 * 
	 * @param awares The collection of {@link DaemonTokenAware} implementations.
	 */
	public void setDaemonToken(DaemonTokenAware... awares) {
		Module module = new Module("Spring Test Module");
		module.setModuleId("spring-test-module");
		final Activator activator = new Activator();
		module.setModuleActivator(activator);
		ModuleFactory.passDaemonToken(module);
		
		Stream.of(awares).forEach(a -> a.setDaemonToken(activator.getDaemonToken()));
	}
}
