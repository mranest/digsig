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

package net.sf.dsig.helpers;

import java.security.cert.X509Certificate;

public class KeyUsageHelper {

	public enum KeyUsage {
		DigitalSignature(0),
		NonRepudiation(1),
		KeyEncipherment(2),
		DataEncipherment(3),
		KeyAgreement(4),
		KeyCertSign(5),
		CRLSign(6),
		EncipherOnly(7),
		DecipherOnly(8);
		private final int pos;
		public int getPos() {
			return pos;
		}
		private KeyUsage(int pos) {
			this.pos = pos;
		}
		public static KeyUsage getByValue(int pos) {
			for (KeyUsage ku: KeyUsage.values()) {
				if (ku.getPos() == pos) {
					return ku;
				}
			}
			
			return null;
		}
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
		for (String purpose: purposes) {
			KeyUsage keyUsage = KeyUsage.valueOf(purpose.trim());
			if (keyUsage == null) {
				throw new UnsupportedOperationException(
						"Unsupported key usage restriction; purpose=" + purpose.trim());
			}
			if (	certificate.getKeyUsage() == null ||
					!certificate.getKeyUsage()[keyUsage.getPos()]) {
				return false;
			}
		}
		
		return true;
	}
	
	public static String printKeyUsage(X509Certificate certificate) {
		StringBuilder sb = new StringBuilder();
		boolean[] keyUsageBitmap = certificate.getKeyUsage();
		
		if (keyUsageBitmap == null) {
			return "(No key usage set)";
		}
		
		for (int i=0; i<keyUsageBitmap.length; i++) {
			if (keyUsageBitmap[i]) {
				if (sb.length() > 0) {
					sb.append(", ");
				}
				sb.append(KeyUsage.getByValue(i));
			}
		}
		
		return sb.toString();
	}
	
}
