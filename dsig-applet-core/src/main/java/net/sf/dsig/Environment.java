/*
 * Copyright 2007-2009 Anestis Georgiadis
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

package net.sf.dsig;

import java.applet.Applet;
import java.beans.PropertyDescriptor;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.swing.JApplet;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.PropertyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *  
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class Environment {
	
	private static final Logger logger = LoggerFactory.getLogger(Environment.class);

	protected Environment() { }
	
	private static Environment SINGLETON = new Environment();

	public static Environment getSingleton() {
		return SINGLETON;
	}
	
	private Applet applet = null;
	
	public void setApplet(Applet applet) {
		this.applet = applet;
	}
	
	private Properties properties = null;
	
	public void setProperties(Properties properties) {
		this.properties = properties;
	}

	/**
	 * <p>Retrieve the environmental value for the specified key; This can come
	 * either from the applet's parameters, as returned by {@link JApplet#getParameter(String)}
	 * method, or from a properties file. Both are optional. 
	 * 
	 * @param key
	 * @return
	 */
	public String getValue(String key) {
		String value = null;
		
		if (properties != null) {
			value = properties.getProperty(key);
		}
		
		if (applet != null && applet.getParameter(key) != null) {
			value = applet.getParameter(key);
		}
		
		return value;
	}
	
	public String[] getValues(String key) {
		List<String> valuesList = new ArrayList<String>();

		// First try with just the key; if it can be found, fall back to the
		// degenerate case of a single value
		String value = getValue(key);
		if (value != null) {
			valuesList.add(value);
			return valuesList.toArray(new String[valuesList.size()]);
		}
		
		// Now try in a loop, looking for key.X, where X is starting from
		// 0 and incrementing; break when no more values can be read
		int pos = 0;
		while (true) {
			String indexedKey = key + "." + pos;
			pos++;
			value = getValue(indexedKey);
			if (value != null) {
				valuesList.add(value);
			} else {
				break;
			}
		}
		
		return valuesList.toArray(new String[valuesList.size()]);
	}
	
	public String getValue(String key, String defaultValue) {
		String value = getValue(key);
		
		if (value == null) {
			return defaultValue;
		} else {
			return value; 
		}
	}

	/**
	 * <p>Initialize an object's public properties, using any environmental
	 * values that have been declared.
	 * 
	 * @param obj the object to initialize.
	 * @param prefix the prefix to add while looking at the environmental values
	 */
	public void init(Object obj, String prefix) {
		// Iterate through all the properties declared for the applet class
		PropertyDescriptor[] descriptors = 
			PropertyUtils.getPropertyDescriptors(obj);
		for (PropertyDescriptor descriptor : descriptors) {
			String propertyName = descriptor.getName();
			logger.debug("Checking" + 
					": obj.class=" + obj.getClass() +
					", propertyName=" + propertyName);
			
			if (descriptor.getWriteMethod() == null) {
				continue;
			}
			
			// Check if an environment parameter has been specified; if so, 
			// override the value with the one supplied
			String key = (prefix != null) ? prefix + propertyName : propertyName;
			
			Object value;
			if (descriptor.getPropertyType().isArray()) {
				value = getValues(key);
			} else {
				value = getValue(key);
			}
			
			if (value != null) {
				logger.debug("Setting" + 
						": obj.class=" + obj.getClass() +
						", propertyName=" + propertyName +
						", value=" + value);
				
				try {
					BeanUtils.setProperty(
							obj, 
							propertyName, 
							value);
				} catch (Exception e) {
					logger.warn("Object initialization error", e);
				}
			}
		}
	}

	public void init(Object obj) {
		init(obj, "");
	}
	
}
