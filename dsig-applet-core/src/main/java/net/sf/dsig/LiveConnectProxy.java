/*
 * Copyright 2007-2010 Anestis Georgiadis
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

import javax.swing.JApplet;

import netscape.javascript.JSException;
import netscape.javascript.JSObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.plugin.dom.DOMService;

import com.sun.java.browser.dom.DOMAccessException;
import com.sun.java.browser.dom.DOMAction;
import com.sun.java.browser.dom.DOMUnsupportedException;

/**
 * <p>This class provides auxiliary methods for utilizing the LiveConnect
 * interface exposed by the JApplet in order to access information on the
 * enclosing page.
 */
public class LiveConnectProxy {
	
	private static final Logger logger = 
			LoggerFactory.getLogger(LiveConnectProxy.class);

	private static final String MSIE_USER_AGENT_DEFAULT = 
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)";
	
	private static final LiveConnectProxy SINGLETON = new LiveConnectProxy();
	
	public static LiveConnectProxy getSingleton() {
		return SINGLETON;
	}
	
	protected LiveConnectProxy() { }

	private DSApplet applet;
	
	public void setApplet(DSApplet applet) {
		this.applet = applet;
	}
	
	public Object eval(String expression) {
		return JSObject.getWindow(applet).eval(expression);
	}
	
	public Object invokeAndWait(DOMAction action) 
	throws DOMAccessException, DOMUnsupportedException {
		return DOMService.getService(applet).invokeAndWait(action);
	}
	
	public void invokeLater(DOMAction action) 
	throws DOMUnsupportedException {
		DOMService.getService(applet).invokeLater(action);
	}
	
	// package visibility is intentional, for unit testing
	String userAgent = null;
	
	public String getUserAgent() {
		if (userAgent == null) {
			try {
				userAgent = applet.getUserAgent();

				if (userAgent == null) {
					// Fallback to invoking navigator.userAgent through JS, if
					// it has not been set as an applet parameter
					userAgent = eval("navigator.userAgent").toString();
				}
			} catch (Exception e) {
				logger.warn("navigator.userAgent evaluation failed; falling back to MSIE default", e);
				userAgent = MSIE_USER_AGENT_DEFAULT;
			}
		}
		
		return userAgent;
	}
	
}
