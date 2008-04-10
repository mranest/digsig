package gr.ageorgiadis.signature;

import org.w3c.dom.Element;
import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;
import org.w3c.dom.html.HTMLOptionElement;
import org.w3c.dom.html.HTMLSelectElement;
import org.w3c.dom.html.HTMLTextAreaElement;

/**
 * The default implementation of the ElementHandler interface. Apart from 
 * defining a (NO-OP) implementation for each method defined in the 
 * ElementHandler, it also handles the multiplicity of HTMLInputElement
 * objects, depending on their type. Subclasses need only override that 
 * 
 * @author ageorgiadis
 */
public abstract class ElementHandlerImpl implements ElementHandler {

	/**
	 * <p>Further drive the event into seperate event handler methods, based on
	 * the type of the HTMLInputElement found. Handling available for types:</p>
	 * <ul>
	 * <li>text</li>
	 * <li>password</li>
	 * <li>button</li>
	 * <li>submit</li>
	 * <li>file</li>
	 * <li>checkbox</li>
	 * <li>radio</li>
	 * <li>hidden</li>
	 * </ul>
	 */
	public void onHTMLInputElement(HTMLInputElement element) {
		String type = element.getType();
		
		if ("text".equals(type)) {
			onHTMLInputTextElement(element);
		} else 
		if ("password".equals(type)) {
			onHTMLInputPasswordElement(element);
		} else 
		if ("button".equals(type)) {
			onHTMLInputButtonElement(element);
		} else 
		if ("submit".equals(type)) {
			onHTMLInputSubmitElement(element);
		} else 
		if ("file".equals(type)) {
			onHTMLInputFileElement(element);
		} else 
		if ("checkbox".equals(type)) {
			onHTMLInputCheckboxElement(element);
		} else 
		if ("radio".equals(type)) {
			onHTMLInputRadioElement(element);
		} else 
		if ("hidden".equals(type)) {
			onHTMLInputHiddenElement(element);
		}
	}

	public void onHTMLFormElement(HTMLFormElement element) {
		/* NO-OP; let the subclass define a proper action */
	}

	public void onHTMLOptionElement(HTMLOptionElement element, Element selectElem) {
		/* NO-OP; let the subclass define a proper action */
	}

	public void onHTMLSelectElement(HTMLSelectElement element) {
		/* NO-OP; let the subclass define a proper action */
	}

	public void onHTMLTextAreaElement(HTMLTextAreaElement element) {
		/* NO-OP; let the subclass define a proper action */
	}

	public void onHTMLInputTextElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputPasswordElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputButtonElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputSubmitElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputFileElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputCheckboxElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputRadioElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
	public void onHTMLInputHiddenElement(HTMLInputElement element) {
		/* NO-OP; let the subclass define a proper action */
	}
	
}
