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

package gr.ageorgiadis.signature;

import gr.ageorgiadis.signature.standard.StandardStrategy;
import gr.ageorgiadis.signature.xmldsig.XMLDSigStrategy;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * The SigningStrategy class encapsulates the process of signing a form. The
 * base abstract class is a Factory object for the concrete subclasses, and 
 * defines the interface for interaction between the strategy object and 
 * the main applet.
 * 
 * @author ageorgiadis
 */
public abstract class SignatureStrategy {

	protected SignatureStrategy() { }
	
	public abstract void setFlags(String flags);
	
	public abstract void setX509Certificate(X509Certificate certificate);
	
	public abstract void setPrivateKey(PrivateKey privateKey);
	
	public abstract ElementHandler getElementHandler();
	
	public abstract String getSignature() throws SignatureException;
	
	public abstract String getPlaintext() throws SignatureException;
	
	public static SignatureStrategy getInstance(String algorithm) 
	throws SignatureException {
		if ("xmldsig".equalsIgnoreCase(algorithm)) {
			return new XMLDSigStrategy();
		}
		if ("debug".equalsIgnoreCase(algorithm)) {
			return new DebugStrategy();
		}
		
		try {
			return new StandardStrategy(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new SignatureException("DSA0010", e);
		}
	}
	
}
