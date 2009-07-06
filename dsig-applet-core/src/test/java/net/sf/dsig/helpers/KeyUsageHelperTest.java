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

package net.sf.dsig.helpers;

import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

public class KeyUsageHelperTest {

	@Test
	public void testHelper() throws Exception {
		KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(getClass().getResourceAsStream("/sample.pfx"), "123456".toCharArray());
		
		// Only one alias expected
		String alias = ks.aliases().nextElement();
		X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);

		String restrictions = "DigitalSignature, NonRepudiation";
		Assert.assertTrue(KeyUsageHelper.validateKeyUsage(certificate, restrictions));

		restrictions = "DigitalSignature, CRLSign";
		Assert.assertFalse(KeyUsageHelper.validateKeyUsage(certificate, restrictions));
		
		Assert.assertEquals(
				"DigitalSignature, NonRepudiation, KeyEncipherment", 
				KeyUsageHelper.printKeyUsage(certificate));
	}
	
	@Test
	public void testHelperNoPurposes() throws Exception {
		X509Certificate certificate = (X509Certificate)
				CertificateFactory.getInstance("X.509").generateCertificate(
							getClass().getResourceAsStream("/sample_nopurposes.cer"));
		
		Assert.assertNotNull(certificate);
		
		String restrictions = "DigitalSignature";
		
		Assert.assertFalse(KeyUsageHelper.validateKeyUsage(certificate, restrictions));
		
		Assert.assertEquals("(No key usage set)", KeyUsageHelper.printKeyUsage(certificate));
	}
	
}
