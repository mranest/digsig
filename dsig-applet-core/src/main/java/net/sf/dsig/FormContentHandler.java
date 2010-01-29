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

package net.sf.dsig;

import net.sf.dsig.impl.StaticStrategyFactory;

/**
 * <p>This class defines the interface for getting the form contents. It is
 * invoked through the {@link FormParser} class.
 * 
 * <p>A concrete implementation is provided by the {@link StaticStrategyFactory} object.
 */
public interface FormContentHandler {

	boolean isElementExcluded(String name);
	
	void onHTMLForm(String id, String name);

	Object onHTMLSelect(String name, boolean multiple);
	
	void onHTMLOption(String value, boolean selected, String text, Object selectObject);
	
	void onHTMLTextArea(String name, String value);
	
	void onHTMLInputButton(String name, String value);
	
	void onHTMLInputCheckbox(String name, String value, boolean checked);
	
	void onHTMLInputFile(String name, String filename, String hashValue);
	
	void onHTMLInputPassword(String name, String value);
	
	void onHTMLInputRadio(String name, String value, boolean checked);
	
	void onHTMLInputSubmit(String name, String value);
	
	void onHTMLInputText(String name, String value);
	
	void onHTMLInputHidden(String name, String value);
	
}
