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

import java.lang.reflect.InvocationTargetException;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FlagsHelper {
	
	private static final Log logger = LogFactory.getLog(FlagsHelper.class);

	/**
	 * Take a comma-delimited list of flags and set the corresponding
	 * properties on the bean Object to true, following JavaBean
	 * conventions. If the name is prepended with '!' set it to false.
	 * @param bean
	 * @param flags
	 */
	public static void setFlags(Object bean, String flags) {
		if (flags == null) {
			return;
		}
		
		for (String flag : flags.split(",")) {
			try {
				if (flag.startsWith("!")) {
					BeanUtils.setProperty(bean, flag.substring(1), "false");
				} else {
					BeanUtils.setProperty(bean, flag, "true");
				}
			} catch (IllegalAccessException e) {
				logger.warn("IllegalAccessException raised", e);
			} catch (InvocationTargetException e) {
				logger.warn("InvocationTargetException raised", e);
			}
		}
	}
	
}
