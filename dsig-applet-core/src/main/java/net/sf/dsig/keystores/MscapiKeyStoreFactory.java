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

package net.sf.dsig.keystores;

import java.security.KeyStore;

import net.sf.dsig.KeyStoreFactory;
import net.sf.dsig.LiveConnectProxy;
import net.sf.dsig.helpers.UserAgentParser;

/**
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class MscapiKeyStoreFactory extends KeyStoreFactory {

	public MscapiKeyStoreFactory() {
		super(null);
	}
	
	public MscapiKeyStoreFactory(KeyStoreFactory next) {
		super(next);
	}
	
	/**
	 * @see net.sf.dsig.KeyStoreFactory#getKeyStoreInternal()
	 */
	@Override
	protected KeyStore getKeyStoreInternal() throws Exception {
		UserAgentParser uap = new UserAgentParser(
				LiveConnectProxy.getSingleton().getUserAgent());
		
		if (!uap.getNames().contains("Mozilla") || uap.getAttributes("Mozilla").isEmpty()) {
			return null;
		}
		
		boolean browserEligible = false;
		for (String attribute : uap.getAttributes("Mozilla")) {
			if (attribute.startsWith("MSIE")) {
				browserEligible = true;
				break;
			}
		}
		
		if (uap.getNames().contains("Chrome")) {
			if (System.getProperty("os.name").startsWith("Windows")) {
				// Only flag the browser as eligible when Chrome is running
				// under Windows
				browserEligible = true;
			}
		}
		
		if (!browserEligible) {
			return null;
		}

		KeyStore ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
		ks.load(null, null);
		
		return ks;
	}
	
}
