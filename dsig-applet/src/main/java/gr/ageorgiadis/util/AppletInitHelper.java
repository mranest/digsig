/*
 * Copyright 2007-2008 Anestis Georgiadis
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

package gr.ageorgiadis.util;

import java.applet.Applet;
import java.beans.PropertyDescriptor;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>An auxiliary class to assist during Applet initialization. Through the use
 * of the PropertyUtils class it retrieves run-time parameters and injects
 * them, JavaBean fashion.</p>
 * <p>All methods offered are static./</p>
 * 
 * @author AGeorgiadis
 */
public class AppletInitHelper {
	
	private static final Log logger = LogFactory.getLog(AppletInitHelper.class);

	/**
	 * Private visibility set to default constructor, to avoid erroneous
	 * instantiation of class objects.
	 */
	private AppletInitHelper() { }
	
	public static void init(Applet applet) {
		// Iterate through all the properties declared for the applet class
		PropertyDescriptor[] descriptors = 
			PropertyUtils.getPropertyDescriptors(applet);
		for (PropertyDescriptor descriptor : descriptors) {
			// Check if an applet parameter has been specified; if so, override
			// the value with the one supplied
			if (applet.getParameter(descriptor.getName()) != null) {
				try {
					BeanUtils.setProperty(applet, descriptor.getName(), 
							applet.getParameter(descriptor.getName()));
				} catch (Exception e) {
					logger.fatal("Applet initialization error", e);
					throw new AppletInitException("Applet initialization error", e);
				}
			}
		}
	}

	private static class AppletInitException extends RuntimeException {
		private static final long serialVersionUID = 1331657180519986590L;
		public AppletInitException(String msg, Throwable t) {
			super(msg, t);
		}
	}
	
}
