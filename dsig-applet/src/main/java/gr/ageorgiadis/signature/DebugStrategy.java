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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;
import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;
import org.w3c.dom.html.HTMLOptionElement;
import org.w3c.dom.html.HTMLTextAreaElement;

/**
 * LoggingStrategy is a simple strategy where every event/action triggered
 * is logged in the system-defined logging facility.
 * 
 * @author ageorgiadis
 */
public class DebugStrategy extends SignatureStrategy {
	
	private static final Log logger = LogFactory.getLog(DebugStrategy.class);

	@Override
	public ElementHandler getElementHandler() {
		return new LoggingElementHandler();
	}

	@Override
	public void setFlags(String flags) {
		logger.info("Flags: " + flags);
	}

	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		logger.info("PrivateKey: " + privateKey);
	}

	@Override
	public void setX509Certificate(X509Certificate certificate) {
		logger.info("X509Certificate: " + certificate);
	}
	
	@Override
	public String getSignature() {
		return null;
	}
	
	@Override
	public String getPlaintext() {
		return null;
	}
	
	private static class LoggingElementHandler extends ElementHandlerImpl {
		
		@Override
		public void onHTMLFormElement(HTMLFormElement element) {
			logger.info("Form: id=" + element.getId() + 
					", name=" + element.getName());
		}
		
		@Override
		public void onHTMLInputElement(HTMLInputElement element) {
			logger.info("Input: name=" + element.getName() + ", type=" + element.getType());
			
			super.onHTMLInputElement(element);
		}
		
		@Override
		public void onHTMLInputButtonElement(HTMLInputElement element) {
			logger.info("Input (button): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputCheckboxElement(HTMLInputElement element) {
			logger.info("Input (checkbox): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputFileElement(HTMLInputElement element) {
			logger.info("Input (file): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputPasswordElement(HTMLInputElement element) {
			logger.info("Input (password): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputRadioElement(HTMLInputElement element) {
			logger.info("Input (radio): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputSubmitElement(HTMLInputElement element) {
			logger.info("Input (submit): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputTextElement(HTMLInputElement element) {
			logger.info("Input (text): name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLOptionElement(HTMLOptionElement element, Element selectElem) {
			logger.info("Option: label=" + element.getLabel() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLTextAreaElement(HTMLTextAreaElement element) {
			logger.info("TextArea: name=" + element.getName() + ", value=" + element.getValue());
		}
		
		@Override
		public void onHTMLInputHiddenElement(HTMLInputElement element) {
			logger.info("Input (hidden): name=" + element.getName() + ", value=" + element.getValue());
		}
	}

}
