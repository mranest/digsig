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

import java.io.File;
import java.security.KeyStore;

import net.sf.dsig.LiveConnectProxy;
import net.sf.dsig.helpers.UserAgentParser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreProxyFactory {

	private static final Logger LOGGER = 
			LoggerFactory.getLogger(KeyStoreProxyFactory.class);
	
	// PKCS11 settings; to be set via initialization in order to drive the
	// creation of the KeyStoreProxy object
	
	private String[] pkcs11Name;
	
	public void setPkcs11Name(String[] pkcs11Name) {
		this.pkcs11Name = pkcs11Name;
	}
	
	public String[] getPkcs11Name() {
		return pkcs11Name;
	}
	
	private String[] pkcs11Library;

	public void setPkcs11Library(String[] pkcs11Library) {
		this.pkcs11Library = pkcs11Library;
	}

	public String[] getPkcs11Library() {
		return pkcs11Library;
	}
	
	public KeyStoreProxy createKeyStoreProxy() {
		MultipleKeyStoreProxy proxy = new MultipleKeyStoreProxy();

		UserAgentParser uap = new UserAgentParser(
				LiveConnectProxy.getSingleton().getUserAgent());
		
		// TODO Implement user-configurable order
		
		// PKCS11 will always be added, based on override configuration that
		// affects the pkcs11Name and pkcs11Library class properties
		addPkcs11KeyStores(proxy);
		
		// Platform KeyStore comes next; Windows first ...
		if (System.getProperty("os.name").startsWith("Windows")) {
			addMSCAPIKeyStore(proxy);
		}
		
		// ... then MacOS X (commented out until we resolve the issues
		// with aliased entries not always returning true for keyEntry)
//		if (System.getProperty("os.name").startsWith("Mac OS X")) {
//			addKeychainKeyStore(proxy);
//		}
		
		// Mozilla KeyStore comes last, if browser is Mozilla-based (only 
		// Mozilla initializes the NSS native libraries)
		if (uap.getNames().contains("Gecko")) {
			addMozillaKeyStore(proxy);
		}


		return proxy;
	}
	
	private void addPkcs11KeyStores(MultipleKeyStoreProxy proxy) {
		// Check that both pkcs11Name and pkcs11Library have been set
		if (	pkcs11Name == null ||
				pkcs11Library == null) {
			return;
		}
		
		int pos = 0;
		
		while (true) {
			final String myPkcs11Name;
			final String mypkcs11Library;
			
			if (	this.pkcs11Name.length > pos &&
					this.pkcs11Library.length > pos) {
				myPkcs11Name = this.pkcs11Name[pos];
				mypkcs11Library = this.pkcs11Library[pos];
			} else {
				break;
			}
			
			pos++;
			
			// Check if PKCS11 library exists
			if (!new File(mypkcs11Library).exists()) {
				LOGGER.info("PKCS11 library not set or missing" +
						"; name=" + myPkcs11Name +
						", library=" + mypkcs11Library);

				continue;
			}
			
			try {
				proxy.add(new Pkcs11KeyStoreFactory(myPkcs11Name, mypkcs11Library)
						.getKeyStore());
				
				LOGGER.debug("Added PKCS11 KeyStore; name=" + myPkcs11Name + ", library=" + mypkcs11Library);
			} catch (Exception ignored) {
				LOGGER.warn("Could not initialize PKCS11 KeyStore", ignored);
			}
		}
	}
	
	private void addMozillaKeyStore(MultipleKeyStoreProxy proxy) {
		try {
			KeyStore ks = new MozillaKeyStoreFactory().getKeyStore();
			if (ks != null) {
				proxy.add(ks);
			}

			LOGGER.debug("Added Mozilla KeyStore");
		} catch (Exception ignored) {
			LOGGER.warn("Could not initialize Mozilla KeyStore", ignored);
		}
	}
	
	private void addMSCAPIKeyStore(MultipleKeyStoreProxy proxy) {
		try {
			KeyStore ks = new MscapiKeyStoreFactory().getKeyStore();
			if (ks != null) {
				proxy.add(ks);
			}
			
			LOGGER.debug("Added MSCAPI KeyStore");
		} catch (Exception ignored) {
			LOGGER.warn("Could not initialize MSCAPI KeyStore", ignored);
		}
	}
	
//	private void addKeychainKeyStore(MultipleKeyStoreProxy proxy) {
//		try {
//			KeyStore ks = new KeychainKeyStoreFactory().getKeyStore();
//			if (ks != null) {
//				proxy.add(ks);
//			}
//			
//			LOGGER.debug("Added Keychain KeyStore");
//		} catch (Exception ignored) {
//			LOGGER.warn("Could not initialize Keychain KeyStore", ignored);
//		}
//	}
	
}
