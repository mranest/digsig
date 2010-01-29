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

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Set;

public interface KeyStoreProxy {

	public Set<String> aliases() throws KeyStoreException;

	public boolean isKeyEntry(String alias) 
	throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;

	public X509Certificate[] getX509CertificateChain(String alias)
	throws KeyStoreException;

	public X509Certificate getX509Certificate(String alias)
	throws KeyStoreException;

	public PrivateKey getPrivateKey(String alias)
	throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;

	public static class KeyStoreProxyException extends RuntimeException {
		private static final long serialVersionUID = -6014494220664334752L;
		public KeyStoreProxyException(String msg, Throwable t) {
			super(msg, t);
		}
	}
}
