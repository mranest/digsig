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

import gr.ageorgiadis.signature.ElementHandlerImpl;
import gr.ageorgiadis.util.HexStringHelper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.html.HTMLCollection;
import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;
import org.w3c.dom.html.HTMLOptionElement;
import org.w3c.dom.html.HTMLSelectElement;
import org.w3c.dom.html.HTMLTextAreaElement;

public class StandardHandler extends ElementHandlerImpl {
	
	private static final Log logger = LogFactory.getLog(StandardHandler.class);
	
	private static final String VERSION_KEY = "version";
	private static final String VERSION = "1.0";
	private static final String DEFAULT_EQUALITY = "=";
	private static final String DEFAULT_DELIMITER = "&";

	protected boolean unselectedCheckboxIncluded = true;
	
	/** Flag to control whether unselected checkbox elements are included in
	 * the XMLDSig or not */
	public void setUnselectedCheckboxIncluded(boolean unselectedCheckboxesIncluded) {
		logger.debug("Setting unselectedCheckboxIncluded to: " + unselectedCheckboxIncluded);
		this.unselectedCheckboxIncluded = unselectedCheckboxesIncluded;
	}
	
	protected boolean unselectedRadioIncluded = false;
	
	/** Flag to control whether unselected radio buttons are included in the 
	 * XMLDSig or not */
	public void setUnselectedRadioIncluded(boolean unselectedRadioIncluded) {
		logger.debug("Setting unselectedRadioIncluded to: " + unselectedRadioIncluded);
		this.unselectedRadioIncluded = unselectedRadioIncluded;
	}
	
	protected String equality = DEFAULT_EQUALITY;
	
	public void setEquality(String equality) {
		this.equality = equality;
	}
	
	protected String delimiter = DEFAULT_DELIMITER;
	
	public void setDelimiter(String delimiter) {
		this.delimiter = delimiter;
	}
	
	protected boolean urlEncoded = true;
	
	public void setUrlEncoded(boolean urlEncoded) {
		this.urlEncoded = urlEncoded;
	}
	
	/** The map of form data that comprise the signable data */
	private final Map<String, String> sortedFormData = new TreeMap<String, String>();

	public StandardHandler() {
		sortedFormData.put(VERSION_KEY, VERSION);
	}
	
	public String getPlaintext() {
		try {
			StringBuilder sb = new StringBuilder();
			for (Iterator<String> i = sortedFormData.keySet().iterator(); i.hasNext(); ) {
				String name = i.next().toString();
				if (sb.length() > 0) {
					sb.append(delimiter);
				}
				sb.append(name);
				sb.append(equality);
				sb.append(urlEncoded ? 
						URLEncoder.encode(sortedFormData.get(name).toString(), "UTF-8") : 
						sortedFormData.get(name).toString());
			}

			return sb.toString();
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void onHTMLFormElement(HTMLFormElement element) {
		// NO-OP
	}
	
	@Override
	public void onHTMLSelectElement(HTMLSelectElement element) {
		String name = element.getName();
		sortedFormData.put(name, "");
		
		HTMLCollection options = element.getOptions();
		if (options != null) {
			for (int i=0; i<options.getLength(); i++) {
				HTMLOptionElement optionElement = (HTMLOptionElement) options.item(i);
				onHTMLOptionElement(optionElement, name);
			}
		} else {
			// Fallback to looking for child nodes named 'option'; it seems
			// some browsers fail to return the OPTION elements using 
			// HTMLSelectElement.getOptions()
			NodeList nl = element.getChildNodes();
			for (int i=0; i<nl.getLength(); i++) {
				Node node = nl.item(i);
				if (	node.getNodeType() == Node.ELEMENT_NODE &&
						node.getNodeName().equalsIgnoreCase("option")) {
					onHTMLOptionElement((HTMLOptionElement) node, name);
				}
			}
		}
	}

	@Override
	public void onHTMLOptionElement(
			HTMLOptionElement element,
			Object selectObject) {
		String name = (String) selectObject;
		String value = sortedFormData.get(name);
		boolean selected = element.getSelected();

		if (selected) {
			sortedFormData.put(name, value.length()>0 ? value+","+element.getValue() : element.getValue());
		}
	}
	
	@Override
	public void onHTMLTextAreaElement(HTMLTextAreaElement element) {
		String name = element.getName();
		String value = element.getValue();
		if (value == null || value.trim().length() == 0) {
			logger.debug("Textarea element is empty; element.name=" + name);
			return;
		}

		sortedFormData.put(name, value);
	}
	
	@Override
	public void onHTMLInputButtonElement(HTMLInputElement element) {
//		sortedFormData.put(element.getName(), element.getValue());
	}
	
	@Override
	public void onHTMLInputCheckboxElement(HTMLInputElement element) {
		boolean checked = element.getChecked();

		if (checked || (!checked && unselectedCheckboxIncluded)) {
			sortedFormData.put(
					element.getName(), 
					checked ? element.getValue() : "");
		}
	}
	
	@Override
	public void onHTMLInputFileElement(HTMLInputElement element) {
		String filename = element.getValue();
		
		// If no file has been selected, don't bother with the 
		// message digest
		if (filename == null || filename.trim().length() == 0) {
			logger.debug("File input element is empty; element.name=" + element.getName());
			return;
		}
		
		// Run a SHA-1 digest on this file's contents
		try {
			File file = new File(filename);
			FileInputStream fis = new FileInputStream(file);
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			byte[] buffer = new byte[1024];
			int count = 0;
			while ((count = fis.read(buffer)) != -1) {
				digest.update(buffer, 0, count);
			}
			fis.close();
			byte[] digestBytes = digest.digest();

			sortedFormData.put(
					element.getName(), 
					HexStringHelper.toHexString(digestBytes));
		} catch (FileNotFoundException e) {
			logger.warn("File not found: " + filename, e);
		} catch (IOException e) {
			logger.warn("I/O error: " + filename, e);
		} catch (NoSuchAlgorithmException e) {
			logger.warn("No such algorithm exception: " + e);
		}
	}
	
	@Override
	public void onHTMLInputPasswordElement(HTMLInputElement element) {
		String name = element.getName();
		String value = element.getValue();
		if (value == null || value.trim().length() == 0) {
			logger.debug("Password input element is empty; element.name=" + name);
			return;
		}

		sortedFormData.put(name, value);
	}
	
	@Override
	public void onHTMLInputRadioElement(HTMLInputElement element) {
		boolean checked = element.getChecked();

		if (checked || (!checked && unselectedRadioIncluded)) {
			sortedFormData.put(
					element.getName(), 
					element.getValue());
		}
	}
	
	@Override
	public void onHTMLInputSubmitElement(HTMLInputElement element) {
//		sortedFormData.put(element.getName(), element.getValue());
	}
	
	@Override
	public void onHTMLInputTextElement(HTMLInputElement element) {
		String name = element.getName();
		String value = element.getValue();
		if (value == null || value.trim().length() == 0) {
			logger.debug("Text input element is empty; element.name=" + name);
			return;
		}

		sortedFormData.put(name, value);
	}
	
	@Override
	public void onHTMLInputHiddenElement(HTMLInputElement element) {
		String name = element.getName();
		String value = element.getValue();
		if (value == null || value.trim().length() == 0) {
			logger.debug("Hidden input element is empty; element.name=" + name);
			return;
		}

		sortedFormData.put(name, value);
	}
	
}
