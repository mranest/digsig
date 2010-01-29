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

public class HexStringHelper {

	private HexStringHelper() { }
	
	public static final String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		
		for (int i=0; i<bytes.length;i++) {
		    String temp = Integer.toHexString(0xFF & bytes[i]);
		    // Take care of bytes 0x00 - 0x0F
		    if (temp.length() < 2) {
		    	sb.append("0");
		    }
		    sb.append(temp);
		}
		
		return sb.toString();
	}
	
	public static final String toHexString(byte[] bytes, boolean toUpperCase) {
		return toUpperCase?toHexString(bytes).toUpperCase():toHexString(bytes);
	}
	
}
