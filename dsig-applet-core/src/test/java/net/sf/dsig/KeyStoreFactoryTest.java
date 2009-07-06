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
import java.security.ProviderException;

import junit.framework.Assert;

import org.junit.Test;

public class KeyStoreFactoryTest {

	@Test
	public void testFactory() throws Exception {
		LiveConnectProxy.getSingleton().userAgent = "";
		
		KeyStoreFactory kfs = KeyStoreFactory.createKeyStoreFactoryChain();
		try {
			kfs.getKeyStore();
			Assert.fail("UnsupportedOperationException not raised");
		} catch (UnsupportedOperationException ignored) { }
		
		LiveConnectProxy.getSingleton().userAgent = 
			"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9";
		
		try {
			kfs.getKeyStore();
			Assert.fail("ProviderException not raised"); // NSS initialization error
		} catch (ProviderException ignored) { }
		
		LiveConnectProxy.getSingleton().userAgent =
			"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)";
		
		KeyStore ks = kfs.getKeyStore();
		Assert.assertEquals("SunMSCAPI", ks.getProvider().getName());
	}
	
}
