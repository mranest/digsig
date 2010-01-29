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

package net.sf.dsig;

import java.util.Properties;

import junit.framework.Assert;
import net.sf.dsig.keystores.KeyStoreProxyFactory;

import org.junit.Test;

public class EnvironmentTest {

	@Test
	public void testEnvironment() throws Exception{
		Properties p = new Properties();
		p.load(getClass().getResourceAsStream("/indexedSettings.properties"));
		Environment.getSingleton().setProperties(p);
		
		KeyStoreProxyFactory kspf = new KeyStoreProxyFactory();
		Environment.getSingleton().init(kspf);
		
		Assert.assertNotNull(kspf.getPkcs11Name());
		Assert.assertNotNull(kspf.getPkcs11Library());
		Assert.assertEquals(2, kspf.getPkcs11Name().length);
		Assert.assertEquals(2, kspf.getPkcs11Library().length);
		
		p.load(getClass().getResourceAsStream("/simpleSettings.properties"));
		Environment.getSingleton().setProperties(p);

		Environment.getSingleton().init(kspf);
		
		Assert.assertNotNull(kspf.getPkcs11Name());
		Assert.assertNotNull(kspf.getPkcs11Library());
		Assert.assertEquals(1, kspf.getPkcs11Name().length);
		Assert.assertEquals(1, kspf.getPkcs11Library().length);
	}
	
}
