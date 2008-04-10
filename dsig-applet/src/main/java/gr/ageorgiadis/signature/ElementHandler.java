package gr.ageorgiadis.signature;

import org.w3c.dom.Element;
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
	
	void onHTMLOptionElement(HTMLOptionElement element, Element selectElem);
	
	void onHTMLTextAreaElement(HTMLTextAreaElement element);
	
}
