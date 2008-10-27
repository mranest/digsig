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

import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;
import org.w3c.dom.html.HTMLOptionElement;
import org.w3c.dom.html.HTMLSelectElement;
import org.w3c.dom.html.HTMLTextAreaElement;

/**
 * ElementHandler interface defines all the event-handling methods that
 * a class should implement, in order to receive those events during the
 * parsing of an event by the FormParser class
 * 
 * @author ageorgiadis
 */
public interface ElementHandler {

	void onHTMLFormElement(HTMLFormElement element);
	
	void onHTMLInputElement(HTMLInputElement element);
	
	void onHTMLSelectElement(HTMLSelectElement element);
	
	void onHTMLOptionElement(HTMLOptionElement element, Object selectObject);
	
	void onHTMLTextAreaElement(HTMLTextAreaElement element);
	
}
