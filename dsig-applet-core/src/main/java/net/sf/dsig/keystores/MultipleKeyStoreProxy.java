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

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class MultipleKeyStoreProxy implements KeyStoreProxy {

	private static final Log LOG = LogFactory.getLog(MultipleKeyStoreProxy.class);
	
	private static final String SUN_MSCAPI_KEY_STORE_CLASS = "sun.security.mscapi.KeyStore";
	
	private Set<BigInteger> serialNumbersAdded = new HashSet<BigInteger>();

	private Map<String, KeyStoreEntryProxy> aliasedEntries =
			new HashMap<String, KeyStoreEntryProxy>();
	
	private boolean addAliasedEntry(KeyStoreEntryProxy proxy) throws KeyStoreException {
		if (proxy == null) {
			return false;
		}
		if (proxy.getX509Certificate() == null) {
			return false;
		}
		
		BigInteger serialNumber = proxy.getX509Certificate().getSerialNumber();
		
		if (serialNumbersAdded.contains(serialNumber)) {
			LOG.debug("Tried to add duplicate certificate; skipping; serialNumber=" + serialNumber);

			return false;
		}
		
		serialNumbersAdded.add(serialNumber);
		aliasedEntries.put(proxy.alias(), proxy);
		
		return true;
	}
	
	public void addSunMSCAPIKeyStore(KeyStore keyStore) throws KeyStoreException {
		// Retrieve KeyStore.keyStoreSpi
		Object keyStoreSpi = getField(keyStore, "keyStoreSpi");

		// Retrieve KeyStoreSpi.entries
		Collection<?> entries = (Collection<?>) 
				getField(keyStoreSpi, "entries");

		// Use 
		for (final Object entry : entries) {
			String originalAlias = (String) getField(entry, "alias");
			final String alias = originalAlias + "-" + entry.hashCode();
			
			KeyStoreEntryProxy proxy = new KeyStoreEntryProxy() {
				@Override
				public String alias() {
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

			addAliasedEntry(proxy);
		}
	}
	
	public void addGenericKeyStore(final KeyStore keyStore) throws KeyStoreException {
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			
			KeyStoreEntryProxy proxy = new KeyStoreEntryProxy() {
				@Override
				public String alias() {
					return alias;
				}
				@Override
				public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
					return (PrivateKey) keyStore.getKey(alias, null);
				}
				@Override
				public X509Certificate getX509Certificate() throws KeyStoreException {
					return keyStore.getCertificate(alias) != null ?
							(X509Certificate) keyStore.getCertificate(alias) :
							(getX509CertificateChain() != null && getX509CertificateChain().length > 0 ?
									getX509CertificateChain()[0] :
									null);
				}
				@Override
				public X509Certificate[] getX509CertificateChain() throws KeyStoreException {
					return (X509Certificate[]) keyStore.getCertificateChain(alias);
				}
				@Override
				public boolean isKeyEntry() throws KeyStoreException {
					return keyStore.isKeyEntry(alias);
				}
			};

			addAliasedEntry(proxy);
		}
	}
	
	public void add(final KeyStore keyStore) throws KeyStoreException {
		if (keyStore.getClass().getName().equals(SUN_MSCAPI_KEY_STORE_CLASS)) {
			addSunMSCAPIKeyStore(keyStore);
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
		return aliasedEntries.get(alias) != null ?
				aliasedEntries.get(alias).getPrivateKey() :
				null;
	}

	@Override
	public X509Certificate getX509Certificate(String alias)
			throws KeyStoreException {
		return aliasedEntries.get(alias) != null ?
				aliasedEntries.get(alias).getX509Certificate() :
				null;
	}

	@Override
	public X509Certificate[] getX509CertificateChain(String alias)
			throws KeyStoreException {
		return aliasedEntries.get(alias) != null ?
				aliasedEntries.get(alias).getX509CertificateChain() :
				null;
	}

	@Override
	public boolean isKeyEntry(String alias) throws KeyStoreException {
		return aliasedEntries.get(alias) != null ?
				aliasedEntries.get(alias).isKeyEntry() :
				null;
	}

	private interface KeyStoreEntryProxy {
		String alias();
		PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;
		X509Certificate getX509Certificate() throws KeyStoreException;
		X509Certificate[] getX509CertificateChain() throws KeyStoreException;
		boolean isKeyEntry() throws KeyStoreException;
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
