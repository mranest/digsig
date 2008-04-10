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

package gr.ageorgiadis.security;

import gr.ageorgiadis.signature.BrowserHelper;
import gr.ageorgiadis.util.ini.ContentHandler;
import gr.ageorgiadis.util.ini.Parser;
import gr.ageorgiadis.util.ini.Parser.MalformedException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.pkcs11.SunPKCS11;

/**
 * BrowserKeyStoreFactory encapsulates the logic of creating the proper
 * KeyStore object, taking into account OS system properties and environmental
 * variables, as required. The target is to have the KeyStore object that
 * can look-up the certificates stored in the browser currently running the
 * applet.
 * 
 * Design Patterns: Singleton
 * 
 * @author AGeorgiadis
 */
public class BrowserKeyStoreFactory {
	
	private static final Log logger = LogFactory.getLog(BrowserKeyStoreFactory.class);

	private static BrowserKeyStoreFactory instance = null;

	public String getProviderName(BrowserHelper browserHelper) {
		switch (browserHelper.getBrowser()) {
		case Safari:
			return null;
		case Msie:
			return "MSCAPI";
		case Mozilla:
			return "PKCS11-NSSCrypto";
		default:
			return null;
		}
	}
	
	private BrowserKeyStoreFactory() { }
	
	public static BrowserKeyStoreFactory getInstance() {
		if (instance == null) {
			instance = new BrowserKeyStoreFactory();
		}
		
		return instance;
	}
	
	public KeyStore createKeyStore(BrowserHelper browserHelper) 
	throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, MalformedException {
		KeyStore ks = null;
		
		switch (browserHelper.getBrowser()) {
		case Safari:
			// TODO
			
			break;
		case Msie:
			ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
			ks.load(null, null);
			
			break;
		case Mozilla:
			Map<MozillaAttribute, String> attributeMap = getMozillaAttributeMap();
			// Initialize the provider only once !!!
			boolean providerRegistered = false;
			for (Provider p : Security.getProviders()) {
				if (p.getName().equals("SunPKCS11-NSSCrypto")) {
					providerRegistered = true;
					break;
				}
			}
			
			if (!providerRegistered) {
				Provider p = getMozillaProvider(attributeMap);
				Security.addProvider(p);
			}
			
			ks = KeyStore.getInstance("PKCS11-NSSCrypto");
			ks.load(new KeyStore.LoadStoreParameter() {
				public ProtectionParameter getProtectionParameter() {
					return new KeyStore.CallbackHandlerProtection(
							new PasswordEntryCallbackHandler());
				}
			});
			
			break;
		default:
			// TDODO 
			
			break;
		}
		
		return ks;
	}
	
	private enum MozillaAttribute {
		NssLibraryDirectory,
		NssSecmodDirectory
	}
	
	private Map<MozillaAttribute, String> getMozillaAttributeMap()
	throws IOException, MalformedException {
		Map<MozillaAttribute, String> attributeMap = new HashMap<MozillaAttribute, String>();

		// Our strategy: Find out the path where the active profile resides.
		// This is the path for initializing the nssSecmodDirectory File object.
		// Moreover, in that path resides a compatibility.ini file, containing
		// a LastPlatformDir entry. This is the path for initializing the
		// nssLibraryDirectory File object.
		
		// TODO If StartWithLastProfile=0, or more than one profiles exist,
		// try to find the active profile
		
		File nssLibraryPath = null;
		File nssSecmodPath = null;
		
		File firefoxProfilesPath = null;
		if (System.getProperty("os.name").startsWith("Windows")) {
			String envDataPath = System.getenv("APPDATA");
			firefoxProfilesPath = new File(envDataPath, "Mozilla/Firefox");
		} else if (System.getProperty("os.name").startsWith("Linux")) {
			String userHomePath = System.getProperty("user.home");
			firefoxProfilesPath = new File(userHomePath, ".mozilla/firefox");
		} else {
			throw new UnsupportedOperationException("Usupported OS: os.name=" +
					System.getProperty("os.name"));
		}
		
		FileInputStream fis = new FileInputStream(
				new File(firefoxProfilesPath, "profiles.ini"));
		ProfileIniContentHandler fich = new ProfileIniContentHandler();
		Parser p = new Parser();
		p.setContentHandler(fich);
		p.parse(fis);
		String defaultProfilePath = fich.getDefaultProfilePath();
		
		if (fich.isRelative()) {
			nssSecmodPath = new File(firefoxProfilesPath, defaultProfilePath);
		} else {
			nssSecmodPath = new File(defaultProfilePath);
		}
		
		fis = new FileInputStream(
				new File(nssSecmodPath, "compatibility.ini"));
		CompatibilityIniContentHandler cich = new CompatibilityIniContentHandler();
		p = new Parser();
		p.setContentHandler(cich);
		p.parse(fis);
		
		nssLibraryPath = new File(cich.getLastPlatformDir());
		
		String nssLibraryDirectory = nssLibraryPath.getAbsolutePath();
		System.out.println("Setting nssLibraryDirectory to: " + nssLibraryDirectory);
		attributeMap.put(MozillaAttribute.NssLibraryDirectory, nssLibraryDirectory);
		
		String nssSecmodDirectory = "\"" + nssSecmodPath.getAbsolutePath() +  "\"";
		logger.info("Setting nssSecmodDirectory to: " + nssSecmodDirectory);
		attributeMap.put(MozillaAttribute.NssSecmodDirectory, nssSecmodDirectory);

		return attributeMap;
	}
	
	private Provider getMozillaProvider(Map<MozillaAttribute, String> attributeMap) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(baos);
		
		ps.println("name = NSSCrypto");
		ps.println("nssLibraryDirectory = " + attributeMap.get(MozillaAttribute.NssLibraryDirectory));
		ps.println("nssSecmodDirectory = " + attributeMap.get(MozillaAttribute.NssSecmodDirectory));
		ps.close();
		
		return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
	}
	
	/**
	 * Our pre-defined ContentHandler implementation for retrieving <b>
	 * the default configuration of Firefox</b>. 
	 * 
	 * @author AGeorgiadis
	 */
	public static class ProfileIniContentHandler implements ContentHandler {
		
		private boolean defaultProfile = false;
		private boolean relative = false;
		private String defaultProfilePath = null;
		
		public boolean isRelative() {
			return relative;
		}
		
		public String getDefaultProfilePath() {
			return defaultProfilePath;
		}
		
		public void onEntry(String name, String value) {
			if ("Name".equals(name)) {
				defaultProfile = "default".equals(value);
			} else if ("IsRelative".equals(name)) {
				relative = "1".equals(value);
			} else if ("Path".equals(name) && defaultProfile) {
				defaultProfilePath = value;
			}
		}

		public void onEnd() { /* NO-OP */ }

		public void onSection(String sectionName) { /* NO-OP */ }

		public void onStart() { /* NO-OP */ }
		
	}
	
	public static class CompatibilityIniContentHandler implements ContentHandler {

		private String lastPlatformDir = null;
		
		public String getLastPlatformDir() {
			return lastPlatformDir;
		}
		
		public void onEntry(String name, String value) {
			if ("LastPlatformDir".equals(name)) {
				lastPlatformDir = value;
			}
		}

		public void onEnd() { /* NO-OP */ }

		public void onSection(String sectionName) { /* NO-OP */ }

		public void onStart() { /* NO-OP */ }
		
	}
	
	public static class PasswordEntryCallbackHandler implements CallbackHandler {

		public void handle(Callback[] callbacks) throws IOException,
				UnsupportedCallbackException {
			for (Callback callback : callbacks) {
				if (callback instanceof PasswordCallback) {
					PasswordCallback passwordCallback = (PasswordCallback) callback;

					String password = JOptionPane.showInputDialog("Please enter the master password:");
					passwordCallback.setPassword(password.toCharArray());
				}
			}
		}
		
	}
	
}
