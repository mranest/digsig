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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.ProtectionParameter;

import net.sf.dsig.KeyStoreFactory;
import net.sf.dsig.keystores.MozillaKeyStoreFactory.PasswordEntryCallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.pkcs11.SunPKCS11;

/**
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class Pkcs11KeyStoreFactory extends KeyStoreFactory {

	private static final Log LOG = LogFactory.getLog(Pkcs11KeyStoreFactory.class);
	
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
	
	public Pkcs11KeyStoreFactory() {
		super(null);
	}
	
	public Pkcs11KeyStoreFactory(KeyStoreFactory next) {
		super(next);
	}
	
	/**
	 * @see net.sf.dsig.KeyStoreFactory#getKeyStoreInternal()
	 */
	@Override
	protected KeyStore getKeyStoreInternal() throws Exception {
		// Check that both pkcs11Name and pkcs11Library have been set
		if (	pkcs11Name == null ||
				pkcs11Library == null) {
			return null;
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
			
			// Check if PKCS11 library is existing
			if (!new File(mypkcs11Library).exists()) {
				LOG.info("PKCS11 library not set or missing" +
						"; name=" + myPkcs11Name +
						", library=" + mypkcs11Library);

				continue;
			}
			
			// Take care to initialize the provider only once !!!
			boolean providerRegistered = false;
			for (Provider p : Security.getProviders()) {
				if (p.getName().equals("SunPKCS11-" + myPkcs11Name)) {
					providerRegistered = true;
					break;
				}
			}
	
			try {
				if (!providerRegistered) {
					Provider p = new SunPKCS11(new ByteArrayInputStream(
								getPkcs11Configuration(myPkcs11Name, mypkcs11Library).getBytes()));
					Security.addProvider(p);
				}
				
				KeyStore ks = KeyStore.getInstance("PKCS11-" + myPkcs11Name);

				ks.load(new KeyStore.LoadStoreParameter() {
					public ProtectionParameter getProtectionParameter() {
						return new KeyStore.CallbackHandlerProtection(
								new PasswordEntryCallbackHandler(myPkcs11Name));
					}
				});
			} catch (Exception e) {
				LOG.warn("Could not initialize keystore; pkcs11Name=" + myPkcs11Name, e);
				
				// Allow control to pass to the next available keystoreFactory
				// for execution
				continue;
			}
		}
		
		return null;
	}

	private String getPkcs11Configuration(String pkcs11Name, String pkcs11Library) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(baos);

		ps.println("name = " + pkcs11Name);
		ps.println("library = " + pkcs11Library);
		
		ps.close();

		String configuration = new String(baos.toByteArray()); 
		LOG.debug("SunPKCS11 configuration:\n" + configuration);
		
		return configuration;
	}

}
