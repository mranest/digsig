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

package net.sf.dsig.impl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import net.sf.dsig.FormContentHandler;
import net.sf.dsig.Strategy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DebugStrategy implements Strategy {

	private static final Logger logger = LoggerFactory.getLogger(DebugStrategy.class);
	
	/**
	 * @see net.sf.dsig.Strategy#getFormContentHandler()
	 */
	@Override
	public FormContentHandler getFormContentHandler() {
		return new DebugContentHandler();
	}

	/**
	 * @see net.sf.dsig.Strategy#sign(java.security.PrivateKey, java.security.cert.X509Certificate)
	 */
	@Override
	public void sign(PrivateKey privateKey, X509Certificate[] certificateChain) {
		logger.debug("PrivateKey=" + privateKey);
		logger.debug("CertificateChain=" + Arrays.asList(certificateChain).toString());
	}
	
	private class DebugContentHandler implements FormContentHandler {

		@Override
		public boolean isElementExcluded(String name) {
			return false;
		}
		
		@Override
		public void onHTMLForm(String id, String name) {
			logger.info("Form: id=" + id + ", name=" + name);
		}

		@Override
		public void onHTMLInputButton(String name, String value) {
			logger.info("InputButton: name=" + name+ ", value=" + value);
		}

		@Override
		public void onHTMLInputCheckbox(String name, String value,
				boolean checked) {
			logger.info("InputCheckbox: name=" + name+ ", value=" + value + ", checked=" + checked);
		}

		@Override
		public void onHTMLInputFile(String name, String filename,
				String hashValue) {
			logger.info("InputFile: name=" + name+ ", filename=" + filename + ", hashValue=" + hashValue);
		}

		@Override
		public void onHTMLInputHidden(String name, String value) {
			logger.info("InputHidden: name=" + name+ ", value=" + value);
		}

		@Override
		public void onHTMLInputPassword(String name, String value) {
			logger.info("InputPassword: name=" + name+ ", value=" + value);
		}

		@Override
		public void onHTMLInputRadio(String name, String value, boolean checked) {
			logger.info("InputRadio: name=" + name+ ", value=" + value + ", checked=" + checked);
		}

		@Override
		public void onHTMLInputSubmit(String name, String value) {
			logger.info("InputSubmit: name=" + name+ ", value=" + value);
		}

		@Override
		public void onHTMLInputText(String name, String value) {
			logger.info("InputText: name=" + name+ ", value=" + value);
		}

		@Override
		public void onHTMLOption(
				String value, 
				boolean selected,
				String text,
				Object selectObject) {
			logger.info("Option: value=" + value + ", selected=" + selected + ", text=" + text +", selectObject=" + selectObject);
		}

		@Override
		public Object onHTMLSelect(String name, boolean multiple) {
			logger.info("Select: name=" + name + ", multiple=" + multiple);
			return null;
		}

		@Override
		public void onHTMLTextArea(String name, String value) {
			logger.info("TextArea: name=" + name+ ", value=" + value);
		}
		
	}
	
}
