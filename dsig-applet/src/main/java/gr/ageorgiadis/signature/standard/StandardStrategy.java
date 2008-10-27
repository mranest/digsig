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

package gr.ageorgiadis.signature.standard;

import gr.ageorgiadis.signature.ElementHandler;
import gr.ageorgiadis.signature.SignatureException;
import gr.ageorgiadis.signature.SignatureStrategy;
import gr.ageorgiadis.util.FlagsHelper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

public class StandardStrategy extends SignatureStrategy {

	private final StandardHandler handler = new StandardHandler();
	
	private final Signature signature;
	
	public StandardStrategy(String algorithm) throws NoSuchAlgorithmException {
		signature = Signature.getInstance(algorithm);
	}
	
	@Override
	public ElementHandler getElementHandler() {
		return handler;
	}

	@Override
	public void setFlags(String flags) {
		FlagsHelper.setFlags(handler, flags);
	}

	private PrivateKey privateKey = null;
	
	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	@Override
	public String getPlaintext() throws SignatureException {
		return handler.getPlaintext();
	}

	@Override
	public String getSignature() throws SignatureException {
		try {
			signature.initSign(privateKey);
			signature.update(getPlaintext().getBytes());
			return new String(Base64.encodeBase64(signature.sign()));
		} catch (InvalidKeyException e) {
			throw new SignatureException("DSA0015", e);
		} catch (java.security.SignatureException e) {
			throw new SignatureException("DSA0013", e);
		}
	}

	@Override
	public void setX509Certificate(X509Certificate certificate) {
		// NO-OP; X509Certificate is not needed with Standard signature strategy
	}

}
