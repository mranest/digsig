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

import java.lang.reflect.Field;
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

/**
 * The KeyStoreHelper is a convenience class that encapsulates any logic
 * pertaining to special handling of KeyStore objects (e.g. SunMSCAPI ones).
 * Use this class instead of the JCA API, for the available methods of
 * this class.
 *
 * @author AGeorgiadis
 */
public class KeyStoreHelper {

	private static final String SUNMSCAPI_PROVIDER_NAME = "SunMSCAPI";
	
	private final Adapter adapter;
	
	public KeyStoreHelper(KeyStore keyStore) 
	throws IllegalArgumentException, IllegalAccessException {
		if (keyStore.getProvider().getName().equals(SUNMSCAPI_PROVIDER_NAME)) {
			adapter = new SunMSCAPIAdapter(keyStore);
		} else {
			adapter = new DelegatingAdapter(keyStore);
		}
	}

	public Set<String> aliases()
	throws KeyStoreException {
		return adapter.aliases();
	}

	public boolean isKeyEntry(String alias)
	throws KeyStoreException {
		return adapter.isKeyEntry(alias);
	}

	public X509Certificate[] getX509CertificateChain(String alias)
	throws KeyStoreException {
		return adapter.getX509CertificateChain(alias);
	}

	public X509Certificate getX509Certificate(String alias)
	throws KeyStoreException {
		return adapter.getX509Certificate(alias);
	}

	public PrivateKey getPrivateKey(String alias, char[] password)
	throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return adapter.getPrivateKey(alias, password);
	}

	private interface Adapter {
		Set<String> aliases() throws KeyStoreException;
		boolean isKeyEntry(String alias) throws KeyStoreException;
		X509Certificate getX509Certificate(String alias) throws KeyStoreException;
		X509Certificate[] getX509CertificateChain(String alias) throws KeyStoreException;
		PrivateKey getPrivateKey(String alias, char[] password)
		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;
	}

	/**
	 * The DelegatingAdapter, as its name eloquently points, delegates requests
	 * to the encapsulated KeyStore instance. It is the default Adapter to use,
	 * when no special reason exist to act otherwise.
	 *
	 * @author AGeorgiadis
	 */
	private static class DelegatingAdapter implements Adapter {

		private final KeyStore keyStore;

		public DelegatingAdapter(KeyStore keyStore) {
			this.keyStore = keyStore;
		}

		public Set<String> aliases()
		throws KeyStoreException {
			Set<String> aliases = new HashSet<String>();
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				aliases.add(e.nextElement());
			}

			return aliases;
		}

		public boolean isKeyEntry(String alias)
		throws KeyStoreException {
			return keyStore.isKeyEntry(alias);
		}

		public X509Certificate getX509Certificate(String alias)
		throws KeyStoreException {
			return (X509Certificate) keyStore.getCertificate(alias);
		}

		public X509Certificate[] getX509CertificateChain(String alias)
				throws KeyStoreException {
			Certificate[] certificateChain = keyStore.getCertificateChain(alias);
			X509Certificate[] x509CertificateChain = new X509Certificate[certificateChain.length];

			for (int i=0; i<certificateChain.length; i++) {
				x509CertificateChain[i] = (X509Certificate) certificateChain[i];
			}

			return x509CertificateChain;
		}

		public PrivateKey getPrivateKey(String alias, char[] password)
		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
			return (PrivateKey) keyStore.getKey(alias, password);
		}
	}
	/**
	 * The SunMSCAPIAdapter is working around the limitation existed in all
	 * SunMSCAPI versions (up to jdk1.6.0) of having multiple aliases containing
	 * the same String. Through reflection, it accesses the underlying data
	 * structures and rectifies the problem.
	 *
	 * Kudos go to the poster of the following message for pointing the way:
	 * http://forum.java.sun.com/thread.jspa?forumID=60&threadID=5168755
	 *
	 * @author AGeorgiadis
	 */
	private static class SunMSCAPIAdapter implements Adapter {

		private final Map<String, Object> aliasEntryMap = new HashMap<String, Object>();;

		private void init(KeyStore keyStore) {
			// Retrieve KeyStore.keyStoreSpi
			Object keyStoreSpi = getField(keyStore, "keyStoreSpi");

			// Retrieve KeyStoreSpi.entries
			Collection<?> entries = (Collection<?>) getField(keyStoreSpi, "entries");

			for (Object entry : entries) {
				String originalAlias = (String) getField(entry, "alias");
				String alias = originalAlias + "-" + entry.hashCode();

				aliasEntryMap.put(alias, entry);
			}
		}

		public SunMSCAPIAdapter(KeyStore keyStore)
		throws IllegalArgumentException, IllegalAccessException {
			init(keyStore);
		}

		public Set<String> aliases() throws KeyStoreException {
			return aliasEntryMap.keySet();
		}

		public boolean isKeyEntry(String alias) throws KeyStoreException {
			Object entry = aliasEntryMap.get(alias);

			if (entry == null) {
				throw new KeyStoreException("Alias '" + alias + "' not found");
			}

			return getField(entry, "privateKey") != null;
		}

		public PrivateKey getPrivateKey(String alias, char[] password)
				throws UnrecoverableKeyException, KeyStoreException,
				NoSuchAlgorithmException {
			Object entry = aliasEntryMap.get(alias);

			if (entry == null) {
				throw new KeyStoreException("Alias '" + alias + "' not found");
			}

			return (PrivateKey) getField(entry, "privateKey");
		}

		public X509Certificate[] getX509CertificateChain(String alias)
				throws KeyStoreException {
			Object entry = aliasEntryMap.get(alias);

			if (entry == null) {
				throw new KeyStoreException("Alias '" + alias + "' not found");
			}

			X509Certificate[] certChain =
				(X509Certificate[]) getField(entry, "certChain");
			return certChain.clone();
		}

		public X509Certificate getX509Certificate(String alias)
				throws KeyStoreException {
			return getX509CertificateChain(alias)[0];
		}
	}

	// Auxiliary reflection methods ----------------------------------------- //

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
						throw new KeyStoreHelperException("Illegal argument: " + name, e);
					} catch (IllegalAccessException e) {
						throw new KeyStoreHelperException("Illegal access: " + name, e);
					}
				}
			}

			// Go up the class hierarchy, until no more superclasses exist
			clazz = clazz.getSuperclass();
		}

		throw new KeyStoreHelperException("Field '" + name + "' not found", null);
	}

	private static class KeyStoreHelperException extends RuntimeException {
		private static final long serialVersionUID = -6014494220664334752L;
		public KeyStoreHelperException(String msg, Throwable t) {
			super(msg, t);
		}
	}

}
