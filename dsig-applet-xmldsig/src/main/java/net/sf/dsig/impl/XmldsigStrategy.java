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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.sf.dsig.FormContentHandler;
import net.sf.dsig.LiveConnectProxy;
import net.sf.dsig.Strategy;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * <p>The strategy exposes the following setters that control its behavior (can
 * be set from applet parameters or from the settings.properties file):
 * <ul>
 * <li>signatureElement - set the name of the element to receive the BASE64
 * encoded xmldsig, when created
 * <li>uncheckedCheckboxIncluded - flag to control whether unchecked check boxes
 * are included in the xmldsig; default is false
 * <li>uncheckedRadioIncluded - flag to control whether unchecked radio boxes
 * are included in the xmldsig; default is false
 * <li>unselectedOptionIncluded - flag to control whether unselected options
 * are included in the xmldsig; default is false
 * <li>excludedElements - a comma-separated list of names of form elements to 
 * exclude from the xmldsig; default is to exclude nothing
 * <li>includedElements - a comma-separated list of names of form elements to
 * include in the xmldsig; default is to include everything
 * 
 * @author <a href="mailto:mranest@gmail.com">Anestis Georgiadis</a>
 */
public class XmldsigStrategy implements Strategy {

	private static final Logger logger = LoggerFactory.getLogger(XmldsigStrategy.class);
	
	private String signatureElement;

	public void setSignatureElement(String signatureElement) {
		this.signatureElement = signatureElement;
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
	
	private String excludedElements = null;
	
	public void setExcludedElements(String excludedElements) {
		this.excludedElements = excludedElements;
	}
	
	private String includedElements = null;
	
	public void setIncludedElements(String includedElements) {
		this.includedElements = includedElements;
	}
	
	private String nonce = null;
	
	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
	
	private Set<String> excludedElementsSet = null;
	
	private Set<String> includedElementsSet = null;

	private String formId;
	
	private XmldsigContentHandler contentHandler = null;
	
	@Override
	public FormContentHandler getFormContentHandler() {
		contentHandler = new XmldsigContentHandler();
		return contentHandler;
	}

	static final DocumentBuilder builder;
	
	static {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			builder = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public void sign(PrivateKey privateKey, X509Certificate[] certificateChain) 
	throws Exception {
		String base64Encoded = signInternal(
				contentHandler.getContentDocument(), 
				privateKey, 
				certificateChain);

		if (signatureElement != null) {
			LiveConnectProxy.getSingleton().eval(
					"document.getElementById('" + formId + "').elements['" + signatureElement + "'].value = \"" + base64Encoded + "\";");
		} else {
			logger.warn("No signatureElement set; signatureDocument=\n" + base64Encoded);
		}
	}

	@Override
	public String signPlaintext(
			String plaintext, 
			PrivateKey privateKey,
			X509Certificate[] certificateChain) throws Exception {
		return signInternal(
				builder.parse(
						new ByteArrayInputStream(
								("<plaintext><![CDATA[" + plaintext + "]]></plaintext>").getBytes("UTF-8"))),
				privateKey,
				certificateChain);
	}
	
	private String signInternal(
			Document contentDocument,
			PrivateKey privateKey,
			X509Certificate[] certificateChain)
	throws Exception {
		Document signatureDocument = 
			new XmldsigSigner().sign(
					privateKey, 
					certificateChain, 
					contentDocument,
					nonce);

		Transformer t = TransformerFactory.newInstance().newTransformer();
		StringWriter w = new StringWriter();
		t.transform(new DOMSource(signatureDocument), new StreamResult(w));
		
		return new String(Base64.encodeBase64(w.toString().getBytes("UTF-8")));
	}
	
	private class XmldsigContentHandler implements FormContentHandler {

		private final Document d;
		
		public Document getContentDocument() {
			return d;
		}
		
		public XmldsigContentHandler() {
			d = builder.newDocument();
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
			
			return excludedElementsSet.contains(name) ||
				(	!includedElementsSet.isEmpty() && 
					!includedElementsSet.contains(name));
		}

		private Element handleHTMLInputElement(String type) {
			Element e = d.createElement("input");
			e.setAttribute("type", type);
			
			return e;
		}
		
		private String handleNull(String value) {
			if (value == null) {
				return "";
			} else {
				return value;
			}
		}
		
		@Override
		public void onHTMLForm(String id, String name) {
			Element e = d.createElement("form");
			
			e.setAttribute("id", id);
			e.setAttribute("name", name);

			d.appendChild(e);		
			
			// Save formId for use when storing the signature document
			formId = id;
		}

		@Override
		public Object onHTMLSelect(String name, boolean multiple) {
			Element e = d.createElement("select");
			
			e.setAttribute("name", name);
			e.setAttribute("multiple", String.valueOf(multiple));
			
			d.getDocumentElement().appendChild(e);
			return e;
		}

		@Override
		public void onHTMLOption(
				String value, 
				boolean selected,
				String text,
				Object selectObject) {
			if (	!selected &&
					!unselectedOptionIncluded) {
				return;
			}
			
			Element selectElem = (Element) selectObject;
			
			Element e = d.createElement("option");
			e.setAttribute("value", handleNull(value));
			e.setAttribute("selected", String.valueOf(selected));
			e.setTextContent(handleNull(text));

			selectElem.appendChild(e);
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
			if (	!checked &&
					!uncheckedCheckboxIncluded) {
				return;
			}
			
			Element e = handleHTMLInputElement("checkbox");
			
			e.setAttribute("name", name);
			e.setAttribute("value", handleNull(value));
			e.setAttribute("checked", String.valueOf(checked));

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLInputFile(
				String name, 
				String filename,
				String hashValue) {
			Element e = handleHTMLInputElement("file");
			
			e.setAttribute("name", name);
			e.setAttribute("filename", filename);
			e.setAttribute("hashValue", hashValue);

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLInputHidden(String name, String value) {
			Element e = handleHTMLInputElement("hidden");
			
			e.setAttribute("name", name);
			e.setAttribute("value", handleNull(value));

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLInputPassword(String name, String value) {
			Element e = handleHTMLInputElement("password");
			
			e.setAttribute("name", name);
			e.setAttribute("value", handleNull(value));

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLInputRadio(
				String name, 
				String value, 
				boolean checked) {
			if (	!checked &&
					uncheckedRadioIncluded) {
				return;
			}
			
			Element e = handleHTMLInputElement("radio");
			
			e.setAttribute("name", name);
			e.setAttribute("value", handleNull(value));
			e.setAttribute("checked", String.valueOf(checked));

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLInputSubmit(String name, String value) {
			// NO-OP
		}

		@Override
		public void onHTMLInputText(String name, String value) {
			Element e = handleHTMLInputElement("text");
			
			e.setAttribute("name", name);
			e.setAttribute("value", handleNull(value));

			d.getDocumentElement().appendChild(e);
		}

		@Override
		public void onHTMLTextArea(String name, String value) {
			Element e = d.createElement("textarea");
			
			e.setAttribute("name", name);
			CDATASection cdataSection = d.createCDATASection(handleNull(value));
			e.appendChild(cdataSection);
			
			d.getDocumentElement().appendChild(e);
		}
		
	}
	
}
