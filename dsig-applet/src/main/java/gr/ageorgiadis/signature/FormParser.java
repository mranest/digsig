package gr.ageorgiadis.signature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Node;
import org.w3c.dom.html.HTMLCollection;
import org.w3c.dom.html.HTMLDocument;
import org.w3c.dom.html.HTMLElement;
import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;
import org.w3c.dom.html.HTMLSelectElement;
import org.w3c.dom.html.HTMLTextAreaElement;

import com.sun.java.browser.dom.DOMAccessor;
import com.sun.java.browser.dom.DOMAction;

/**
 * FormParser class handles the task of walking the HTML Document object 
 * provided via LiveConnect, searching at first for a specific form, and then
 * triggering certain events on a FormHandler interface, based on the type
 * of element found in the form.
 * 
 * @author AGeorgiadis
 */
public class FormParser {
	
	private static final Log logger = LogFactory.getLog(FormParser.class);

	/** ElementHandler interface receives the events generated while
	 * traversing the form */
	private ElementHandler elementHandler = null;

	public ElementHandler getElementHandler() {
		return elementHandler;
	}

	public void setElementHandler(ElementHandler elementHandler) {
		this.elementHandler = elementHandler;
	}
	
	private final String formId;
	
	private final DSApplet applet;
	
	public FormParser(DSApplet applet, String formId) {
		this.applet = applet;
		this.formId = formId;
		
		logger.debug("FormParser initiated: formId=" + formId);
	}
	
	/**
	 * <p>Retrieve a DOMAction object that will be passed in the following code
	 * that the applet is running on the event of the submit/sign button:</p>
	 * <pre>
	 * DOMService service = DOMService.getService(Applet);
	 * service.invokeAndWait(FormParser.getParsingDOMAction());
	 * </pre>
	 * <p>This should trigger the discovery and parsing of the HTML form
	 * that, will in turn trigger the events on the bound ElementHandler
	 * </p>
	 * @param applet
	 * @return
	 */
	DOMAction getParsingDOMAction() {
		return new ParsingDOMAction();
	}
	
	private class ParsingDOMAction implements DOMAction {
		
		public Object run(DOMAccessor accessor) {
			HTMLDocument document = (HTMLDocument) accessor.getDocument(applet);
			HTMLElement formElement = (HTMLElement) document.getElementById(formId);
			
			if (formElement == null || !(formElement instanceof HTMLFormElement)) {
				logger.error("Id: " + formId + " does not exist or is not bound to a form element");
				
				// Since the run() method is declared by the DOMAction interface
				// as not throwing an Exception (but returning a generic Object),
				// by convention we will return an Exception object, and the
				// code spawning using this DOMAction will retrieve it and throw
				// it, in case an Exception instance is returned
				return new IllegalArgumentException("Id: " + formId + " does not exist or is not bound to a form element");
			}
			
			return traverseFormElements((HTMLFormElement) formElement);
		}
		
		protected Object traverseFormElements(HTMLFormElement formElement) {
			handleNode(formElement);
			
			HTMLCollection formElements = formElement.getElements();
			for (int i=0; i<formElements.getLength(); i++) {
				handleNode(formElements.item(i));
			}
			
			return null;
		}
		
		protected Object handleNode(Node node) {
			if (elementHandler == null) {
				return null;
			}
			
			if (node instanceof HTMLFormElement) {
				HTMLFormElement formElement = (HTMLFormElement) node;
				logger.debug("Found HTMLFormElement: id=" + formElement.getId());

				elementHandler.onHTMLFormElement(formElement);
			} else 
			if (node instanceof HTMLInputElement) {
				// We expect the three (at most) elements that the applet is
				// expected to fill to be either input|text or input|hidden
				// elements. In order to avoid taking their value into the
				// signature block, we check against the name of the input
				// element found.
				HTMLInputElement inputElement = (HTMLInputElement) node;
				logger.debug("Found HTMLInputElement: name=" + inputElement.getName());
				
				if (!matchesResultElements(inputElement.getName())) {
					elementHandler.onHTMLInputElement(inputElement);
				}
			} else
			if (node instanceof HTMLSelectElement) {
				HTMLSelectElement selectElement = (HTMLSelectElement) node;
				logger.debug("Found HTMLSelectElement: name=" + selectElement.getName());

				elementHandler.onHTMLSelectElement((HTMLSelectElement) node);
			} /* else
			if (node instanceof HTMLOptionElement) {
				HTMLOptionElement optionElement = (HTMLOptionElement) node;
				logger.debug("Found HTMLOptionElement: value=" + optionElement.getValue());

				elementHandler.onHTMLOptionElement((HTMLOptionElement) node);
			} */ else
			if (node instanceof HTMLTextAreaElement) {
				HTMLTextAreaElement textAreaElement = (HTMLTextAreaElement) node;
				logger.debug("Found HTMLTextAreaElement: name=" + textAreaElement.getName());

				elementHandler.onHTMLTextAreaElement((HTMLTextAreaElement) node);
			}
			
			return null;
		}
		
		private boolean matchesResultElements(String name) {
			if (name == null) {
				return false;
			}
			
			if (	applet.getSerialNumberElement() != null &&
					applet.getSerialNumberElement().equals(name)) {
				return true;
			}
			if (	applet.getPlaintextElement() != null &&
					applet.getPlaintextElement().equals(name)) {
				return true;
			}
			if (	applet.getSignatureElement() != null &&
					applet.getSignatureElement().equals(name)) {
				return true;
			}
			
			return false;
		}
	}
	
}
