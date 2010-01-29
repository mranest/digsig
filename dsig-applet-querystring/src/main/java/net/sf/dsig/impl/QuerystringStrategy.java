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

package net.sf.dsig.impl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import net.sf.dsig.FormContentHandler;
import net.sf.dsig.LiveConnectProxy;
import net.sf.dsig.Strategy;
import net.sf.dsig.helpers.HexStringHelper;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class QuerystringStrategy implements Strategy {

	private static final Logger logger = LoggerFactory.getLogger(QuerystringStrategy.class);
	
	private static final String DEFAULT_EQUALITY = "=";
	
	private static final String DEFAULT_DELIMITER = "&";
	
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";

	private String signatureElement;

	public void setSignatureElement(String signatureElement) {
		this.signatureElement = signatureElement;
	}
	
	private String plaintextElement;
	
	public void setPlaintextElement(String plaintextElement) {
		this.plaintextElement = plaintextElement;
	}
	
	private String serialNumberElement;
	
	public void setSerialNumberElement(String serialNumberElement) {
		this.serialNumberElement = serialNumberElement;
	}

	private String equality = DEFAULT_EQUALITY;
	
	public void setEquality(String equality) {
		this.equality = equality;
	}
	
	private String delimiter = DEFAULT_DELIMITER;
	
	public void setDelimiter(String delimiter) {
		this.delimiter = delimiter;
	}
	
	protected boolean urlEncoded = true;
	
	public void setUrlEncoded(boolean urlEncoded) {
		this.urlEncoded = urlEncoded;
	}
	
	private boolean uncheckedCheckboxIncluded = false;
	
	public void setUncheckedCheckboxIncluded(boolean uncheckedCheckboxIncluded) {
		this.uncheckedCheckboxIncluded = uncheckedCheckboxIncluded;
	}
	
	private boolean uncheckedRadioIncluded = false;
	
	public void setUncheckedRadioIncluded(boolean uncheckedRadioIncluded) {
		this.uncheckedRadioIncluded = uncheckedRadioIncluded;
	}
	
	private boolean unselectedOptionIncluded = false;
	
	public void setUnselectedOptionIncluded(boolean unselectedOptionIncluded) {
		this.unselectedOptionIncluded = unselectedOptionIncluded;
	}
	
	private String signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
	
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	
	private boolean serialNumberInHexadecimal = false;
	
	public void setSerialNumberInHexadecimal(boolean serialNumberInHexadecimal) {
		this.serialNumberInHexadecimal = serialNumberInHexadecimal;
	}
	
	private String excludedElements = null;
	
	public void setExcludedElements(String excludedElements) {
		this.excludedElements = excludedElements;
	}
	
	private String includedElements = null;
	
	public void setIncludedElements(String includedElements) {
		this.includedElements = includedElements;
	}
	
	private Set<String> excludedElementsSet = null;
	
	private Set<String> includedElementsSet = null;

	private String formId;
	
	private QuerystringContentHandler contentHandler;
	
	@Override
	public FormContentHandler getFormContentHandler() {
		contentHandler = new QuerystringContentHandler();
		return contentHandler;
	}

	@Override
	public void sign(
			PrivateKey privateKey, 
			X509Certificate[] certificateChain)
	throws Exception {
		String plaintext = contentHandler.getPlaintext();
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initSign(privateKey);
		signature.update(plaintext.getBytes());
		String signatureAsString = new String(Base64.encodeBase64(signature.sign()));
		
		if (signatureElement != null) {
			LiveConnectProxy.getSingleton().eval(
					"document.getElementById('" + formId + "').elements['" + signatureElement + "'].value = \"" + signatureAsString + "\";");
		} else {
			logger.warn("No signatureElement set");
		}
		
		if (plaintextElement != null) {
			LiveConnectProxy.getSingleton().eval(
					"document.getElementById('" + formId + "').elements['" + plaintextElement + "'].value = \"" + plaintext + "\";");
		} else {
			logger.warn("No plaintextElement set");
		}
		
		String serialNumberAsString = serialNumberInHexadecimal ?
				HexStringHelper.toHexString(certificateChain[0].getSerialNumber().toByteArray()) :
				"" + certificateChain[0].getSerialNumber();
		if (serialNumberElement != null) {
			LiveConnectProxy.getSingleton().eval(
					"document.getElementById('" + formId + "').elements['" + serialNumberElement + "'].value = \"" + serialNumberAsString + "\";");
		} else {
			logger.warn("No serialNumberElement set");
		}
	}

	private class QuerystringContentHandler implements FormContentHandler {

		private StringBuilder plaintextSb = new StringBuilder();
		
		public String getPlaintext() {
			return plaintextSb.toString();
		}
		
		protected void addFormData(String key, String value) {
			try {
				if (plaintextSb.length() > 0) {
					plaintextSb.append(delimiter);
				}
				plaintextSb.append(key);
				plaintextSb.append(equality);
				if (value != null) {
					plaintextSb.append(urlEncoded ?
							URLEncoder.encode(value, "UTF-8") :
							value);
				}
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
		}

		public boolean isElementExcluded(String name) {
			if (excludedElementsSet == null) {
				excludedElementsSet = new HashSet<String>();
				
				if (excludedElements != null) {
					String[] excludedNames = excludedElements.split(",");
					for (String excludedName : excludedNames) {
						excludedElementsSet.add(excludedName.trim());
					}
				}
			}
			
			if (includedElementsSet == null) {
				includedElementsSet = new HashSet<String>();
				
				if (includedElements != null) {
					String[] includedNames = includedElements.split(",");
					for (String includedName: includedNames) {
						includedElementsSet.add(includedName.trim());
					}
				}
			}
			
			// Exclude the element that is configured to receive the xmldsig
			if (name.equals(signatureElement)) {
				return true;
			}
			
			return 	name.equals(signatureElement) ||
					name.equals(plaintextElement) ||
					name.equals(serialNumberElement);
		}

		@Override
		public void onHTMLForm(String id, String name) {
			// Save formId for use when storing the signature document
			formId = id;
		}

		@Override
		public void onHTMLInputButton(String name, String value) {
			// NO-OP
		}

		@Override
		public void onHTMLInputCheckbox(
				String name, 
				String value,
				boolean checked) {
			if (checked || (!checked && uncheckedCheckboxIncluded)) {
				addFormData(
						name, 
						checked ? value : "");
			}
		}

		@Override
		public void onHTMLInputFile(
				String name, 
				String filename,
				String hashValue) {
			addFormData(
					name, 
					hashValue);
		}

		@Override
		public void onHTMLInputHidden(String name, String value) {
			addFormData(name, value);
		}

		@Override
		public void onHTMLInputPassword(String name, String value) {
			addFormData(name, value);
		}

		@Override
		public void onHTMLInputRadio(String name, String value, boolean checked) {
			if (checked || (!checked && uncheckedRadioIncluded)) {
				addFormData(
						name, 
						checked ? value : "");
			}
		}

		@Override
		public void onHTMLInputSubmit(String name, String value) {
			// NO-OP
		}

		@Override
		public void onHTMLInputText(String name, String value) {
			addFormData(name, value);
		}

		@Override
		public void onHTMLOption(
				String value, 
				boolean selected, 
				String text,
				Object selectObject) {
			String name = (String) selectObject;

			if (selected || (!selected && unselectedOptionIncluded)) {
				addFormData(name, value);
			}
		}

		@Override
		public Object onHTMLSelect(String name, boolean multiple) {
			return name;
		}

		@Override
		public void onHTMLTextArea(String name, String value) {
			addFormData(name, value);
		}
		
	}
	
}
