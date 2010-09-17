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

package net.sf.dsig.keystores;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MultipleKeyStoreProxy implements KeyStoreProxy {

	private static final Logger LOGGER = 
			LoggerFactory.getLogger(MultipleKeyStoreProxy.class);
	
	private static final String SUNMSCAPI_PROVIDER = "SunMSCAPI";
	
	private static final String APPLE_PROVIDER = "Apple";
	
	private Set<BigInteger> serialNumbersAdded = new HashSet<BigInteger>();

	private Map<String, KeyStoreEntryProxy> aliasedEntries =
			new HashMap<String, KeyStoreEntryProxy>();
	
	private boolean addAliasedEntry(KeyStoreEntryProxy proxy) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		if (proxy == null) {
			return false;
		}
		if (proxy.getX509Certificate() == null) {
			return false;
		}
		
		BigInteger serialNumber = proxy.getX509Certificate().getSerialNumber();
		
		String sameSerialNumberAlias = null;
		for (Entry<String, KeyStoreEntryProxy> each: aliasedEntries.entrySet()) {
			if (each.getValue().getX509Certificate().getSerialNumber().equals(serialNumber)) {
				sameSerialNumberAlias = each.getKey();
			}
		}
		
		if (sameSerialNumberAlias != null) {
			KeyStoreEntryProxy sameSerialNumberProxy = aliasedEntries.get(sameSerialNumberAlias);
			
			if (sameSerialNumberProxy.isKeyEntry()) {
				// Same serial number proxy has a proper entry key; prefer that
				LOGGER.debug("Tried to add duplicate certificate, and previous one has a keyEntry; skipping; alias={}, serialNumber={}", 
						proxy.getAlias(), serialNumber);
				
				return false;
			}
		}
		
		if (sameSerialNumberAlias != null) {
			aliasedEntries.remove(sameSerialNumberAlias);
			
			LOGGER.debug("Removed previous duplicate certificate; alias={}, serialNumber={}",
					sameSerialNumberAlias, serialNumber);
		}
		
		serialNumbersAdded.add(serialNumber);
		
		LOGGER.debug("Added certificate; alias={}, serialNumber={}", proxy.getAlias(), serialNumber);
		
		aliasedEntries.put(proxy.getAlias(), proxy);
		
		return true;
	}
	
	public void addSunMSCAPIKeyStore(KeyStore keyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		// Retrieve KeyStore.keyStoreSpi
		Object keyStoreSpi = getField(keyStore, "keyStoreSpi");

		// Retrieve KeyStoreSpi.entries
		Collection<?> entries = (Collection<?>) 
				getField(keyStoreSpi, "entries");

		// Use 
		for (final Object each : entries) {
			final String originalAlias = (String) getField(each, "alias");
			
			KeyStoreEntryProxy proxy = new KeyStoreEntryProxy() {
				private final String alias = originalAlias + "-" + each.hashCode();
				private final Object entry = each;
				@Override
				public String getAlias() {
					return alias;
				}
				@Override
				public PrivateKey getPrivateKey() {
					return (PrivateKey) getField(entry, "privateKey");
				}
				@Override
				public X509Certificate getX509Certificate() {
					return getX509CertificateChain() != null && getX509CertificateChain().length > 0 ?
							getX509CertificateChain()[0] :
							null;
				}
				@Override
				public X509Certificate[] getX509CertificateChain() {
					return (X509Certificate[]) getField(entry, "certChain");
				}
				@Override
				public boolean isKeyEntry() {
					return getPrivateKey() != null;
				}
			};

			LOGGER.debug("Created MSCAPI KeyStoreEntryProxy; alias={}", proxy.getAlias());

			addAliasedEntry(proxy);
		}
	}
	
	public void addGenericKeyStore(final KeyStore keyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		addGenericKeyStore(keyStore, true); 
	}
	
	public void addGenericKeyStore(final KeyStore keyStore, final boolean passwordNull) 
	throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			
			KeyStoreEntryProxy proxy = new KeyStoreEntryProxy() {
				@Override
				public String getAlias() {
					return alias;
				}
				@Override
				public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
					// non-null override is used by the Apple Keychain KeyStore
					// implementation, which expects a non-null parameter to 
					// trigger it to work
					LOGGER.debug("Trying to retrieve privateKey; alias={}", alias);
					
					return (PrivateKey) keyStore.getKey(
							alias, 
							passwordNull ? null : "not-null".toCharArray());
				}
				@Override
				public X509Certificate getX509Certificate() throws KeyStoreException {
					// First try keyStore.getCertificate(...)
					X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
					
					if (certificate != null) {
						return certificate;
					}
				
					// Fall back to using keyStore.getCertificateChain(...)
					return getX509CertificateChain() != null && getX509CertificateChain().length > 0 ?
							getX509CertificateChain()[0] :
							null;
				}
				
				@Override
				public X509Certificate[] getX509CertificateChain() throws KeyStoreException {
					X509Certificate[] certificates = null;
					
					// First try keyStore.getCertificateChain(...)
					Certificate[] certificateChain = keyStore.getCertificateChain(alias);
					if (certificateChain != null) {
						certificates = new X509Certificate[certificateChain.length];
						for (int i=0; i<certificates.length; i++) {
							certificates[i] = (X509Certificate) certificateChain[i];
						}
	
						return certificates;
					}
					
					// Fall back to using keyStore.getCertificate(...)
					X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
					
					if (certificate != null) {
						certificates = new X509Certificate[1];
						certificates[0] = certificate;
					}
					
					return certificates;
				}

				@Override
				public boolean isKeyEntry() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
					boolean keyEntry = keyStore.isKeyEntry(alias);

					return keyEntry ? keyEntry : getPrivateKey() != null;
				}
			};

			addAliasedEntry(proxy);
		}
	}
	
	public void add(final KeyStore keyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		LOGGER.debug("About to handle keyStore of provider [{}]", 
				keyStore.getProvider().getName());
		
		if (keyStore.getProvider().getName().equals(SUNMSCAPI_PROVIDER)) {
			LOGGER.debug("Enabling special handling for SunMSCAPI provider");
			
			addSunMSCAPIKeyStore(keyStore);
		} else if (keyStore.getProvider().getName().equals(APPLE_PROVIDER)) {
			addGenericKeyStore(keyStore, false);
		} else {
			addGenericKeyStore(keyStore);
		}
	}
	
	@Override
	public Set<String> aliases() throws KeyStoreException {
		return aliasedEntries.keySet();
	}

	@Override
	public PrivateKey getPrivateKey(String alias)
	throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		KeyStoreEntryProxy entryProxy = aliasedEntries.get(alias);
		
		return entryProxy != null ?
				entryProxy.getPrivateKey() :
				null;
	}

	@Override
	public X509Certificate getX509Certificate(String alias)
			throws KeyStoreException {
		KeyStoreEntryProxy entryProxy = aliasedEntries.get(alias);
		
		return entryProxy != null ?
				entryProxy.getX509Certificate() :
				null;
	}

	@Override
	public X509Certificate[] getX509CertificateChain(String alias)
			throws KeyStoreException {
		KeyStoreEntryProxy entryProxy = aliasedEntries.get(alias);
		
		return entryProxy != null ?
				entryProxy.getX509CertificateChain() :
				null;
	}

	@Override
	public boolean isKeyEntry(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		KeyStoreEntryProxy entryProxy = aliasedEntries.get(alias);
		
		return entryProxy != null ?
				entryProxy.isKeyEntry() :
				null;
	}

	private interface KeyStoreEntryProxy {
		String getAlias();
		PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;
		X509Certificate getX509Certificate() throws KeyStoreException;
		X509Certificate[] getX509CertificateChain() throws KeyStoreException;
		boolean isKeyEntry() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;
	}
	
	public static Object getField(Object instance, String name) {
		Class<?> clazz = instance.getClass();
		while (clazz != null) {
			Field[] fields = clazz.getDeclaredFields();
			for (int i=0; i<fields.length; i++) {
				Field field = fields[i];
				if (field.getName().equals(name)) {
					field.setAccessible(true);
					try {
						return field.get(instance);
					} catch (IllegalArgumentException e) {
						throw new KeyStoreProxyException("Illegal argument: " + name, e);
					} catch (IllegalAccessException e) {
						throw new KeyStoreProxyException("Illegal access: " + name, e);
					}
				}
			}

			// Go up the class hierarchy, until no more superclasses exist
			clazz = clazz.getSuperclass();
		}

		throw new KeyStoreProxyException("Field '" + name + "' not found", null);
	}

}
