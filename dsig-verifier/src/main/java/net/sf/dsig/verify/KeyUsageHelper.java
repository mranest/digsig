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

package net.sf.dsig.verify;

import java.security.cert.X509Certificate;

/**
 * 
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class KeyUsageHelper {

	public static final String[] KEY_USAGE = {
		"DigitalSignature",
		"NonRepudiation",
		"KeyEncipherment",
		"DataEncipherment",
		"KeyAgreement",
		"KeyCertSign",
		"CRLSign",
		"EncipherOnly",
		"DecipherOnly"
	};
	
	public static String getKeyUsageByValue(int pos) {
		return KEY_USAGE[pos];
	}
	
	public static int getValueByKeyUsage(String keyUsage) {
		for (int i=0; i<KEY_USAGE.length; i++) {
			if (KEY_USAGE[i].equals(keyUsage)) {
				return i;
			}
		}
		
		return -1;
	}
	
	/**
	 * 
	 * @param certificate
	 * @param keyUsageRestrictions
	 * @return
	 */
	public static boolean validateKeyUsage(
			X509Certificate certificate,
			String keyUsageRestrictions) {
		String[] purposes = keyUsageRestrictions.split(","); 
		for (int i=0; i<purposes.length; i++) {
			String keyUsage = purposes[i].trim();
			int pos = getValueByKeyUsage(keyUsage);
			if (pos == -1) {
				throw new UnsupportedOperationException(
						"Unsupported key usage restriction; purpose=" + keyUsage);
			}
			if (	certificate.getKeyUsage() == null ||
					!certificate.getKeyUsage()[pos]) {
				return false;
			}
		}
		
		return true;
	}
	
	public static String printKeyUsage(X509Certificate certificate) {
		StringBuffer sb = new StringBuffer();
		boolean[] keyUsageBitmap = certificate.getKeyUsage();
		
		if (keyUsageBitmap == null) {
			return "(No key usage set)";
		}
		
		for (int i=0; i<keyUsageBitmap.length; i++) {
			if (keyUsageBitmap[i]) {
				if (sb.length() > 0) {
					sb.append(", ");
				}
				sb.append(getKeyUsageByValue(i));
			}
		}
		
		return sb.toString();
	}
	
}
