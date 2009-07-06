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

import java.security.KeyStore;

import net.sf.dsig.keystores.MozillaKeyStoreFactory;
import net.sf.dsig.keystores.MscapiKeyStoreFactory;
import net.sf.dsig.keystores.Pkcs11KeyStoreFactory;

/**
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class KeyStoreFactory {

	private final KeyStoreFactory next;
	
	protected KeyStoreFactory(KeyStoreFactory next) {
		this.next = next;
	}
	
	public final KeyStore getKeyStore() throws Exception {
		KeyStore ks = getKeyStoreInternal();
		if (ks != null) {
			return ks;
		}
		
		if (next != null) {
			return next.getKeyStore();
		}

		throw new UnsupportedOperationException("Cannot create KeyStore; userAgent=" +
				LiveConnectProxy.getSingleton().getUserAgent());
	}
	
	protected KeyStore getKeyStoreInternal() throws Exception {
		return null;
	}
	
	/**
	 * Declaration of KeyStoreFactory objects in the chain is the reverse of
	 * the intended order of usage
	 * @return
	 */
	public static KeyStoreFactory createKeyStoreFactoryChain() {
		KeyStoreFactory kfs;
		
		kfs = new MozillaKeyStoreFactory();
		Environment.getSingleton().init(kfs);
		
		kfs = new MscapiKeyStoreFactory(kfs);
		Environment.getSingleton().init(kfs);
		
		kfs = new Pkcs11KeyStoreFactory(kfs);
		Environment.getSingleton().init(kfs);
		
		kfs = new KeyStoreFactory(kfs);
		Environment.getSingleton().init(kfs);
		
		return kfs;
	}
	
}
