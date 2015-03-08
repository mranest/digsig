/*
 * Copyright 2007-2014 Anestis Georgiadis
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

import net.sf.dsig.helpers.HexStringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.html.*;

import java.applet.Applet;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * FormParser class handles the task of walking the HTML Document object 
 * provided via LiveConnect, searching at first for a specific form, and then
 * triggering certain events on a FormHandler interface, based on the type
 * of element found in the form.
 */
public class FormParser {
    
    private static final Logger logger = LoggerFactory.getLogger(FormParser.class);

    /** ElementHandler interface receives the events generated while
     * traversing the form */
    private FormContentHandler contentHandler = null;

    public void setContentHandler(FormContentHandler contentHandler) {
        this.contentHandler = contentHandler;
    }
    
    private final String formId;
    
    private final DSApplet applet;
    
    public FormParser(DSApplet applet, String formId) {
        this.applet = applet;
        this.formId = formId;
        
        logger.debug("FormParser initiated: formId=" + formId);
    }

    @SuppressWarnings("unchecked")
    public Object parse() throws Exception {
        Class c = Class.forName("com.sun.java.browser.plugin2.DOM");
        Method m = c.getMethod("getDocument", Applet.class);

        HTMLDocument document = (HTMLDocument) m.invoke(null, applet);
        HTMLElement formElement = (HTMLElement) document.getElementById(formId);

        if (formElement == null || !(formElement instanceof HTMLFormElement)) {
            logger.error("Id: " + formId + " does not exist or is not bound to a form element");

            throw new IllegalArgumentException("Id: " + formId + " does not exist or is not bound to a form element");
        } else {
            return traverseFormElements((HTMLFormElement) formElement);
        }
    }

    protected Object traverseFormElements(HTMLFormElement formElement) {
        handleNode(formElement);

        // Traverse form elements; this is not a deep-copy traversal
        // (i.e. OPTION elements are not handled for SELECT elements)
        HTMLCollection formElements = formElement.getElements();
        for (int i=0; i<formElements.getLength(); i++) {
            handleNode(formElements.item(i));
        }

        return null;
    }

    protected Object handleNode(Node node) {
        if (contentHandler == null) {
            return null;
        }


        if (node instanceof HTMLFormElement) {
            HTMLFormElement formElement = (HTMLFormElement) node;
            logger.debug("Found HTMLFormElement: id=" + formElement.getId());

            onHTMLFormElement(formElement);
        } else
        if (node instanceof HTMLInputElement) {
            // We expect the three (at most) elements that the applet is
            // expected to fill to be either input|text or input|hidden
            // elements. In order to avoid taking their value into the
            // signature block, we check against the name of the input
            // element found.
            HTMLInputElement inputElement = (HTMLInputElement) node;
            if (inputElement.getDisabled()) {
                logger.debug("Skipping disabled HTMLInputElement: name=" + inputElement.getName());
                return null;
            }

            logger.debug("Found HTMLInputElement: name=" + inputElement.getName());

            onHTMLInputElement(inputElement);
        } else
        if (node instanceof HTMLSelectElement) {
            HTMLSelectElement selectElement = (HTMLSelectElement) node;
            if (selectElement.getDisabled()) {
                logger.debug("Skipping disabled HTMLSelectElement: name=" + selectElement.getName());
                return null;
            }

            logger.debug("Found HTMLSelectElement: name=" + selectElement.getName());

            onHTMLSelectElement((HTMLSelectElement) node);
        } else
        if (node instanceof HTMLTextAreaElement) {
            HTMLTextAreaElement textAreaElement = (HTMLTextAreaElement) node;
            if (textAreaElement.getDisabled()) {
                logger.debug("Skipping disabled HTMLTextAreaElement: name=" + textAreaElement.getName());
                return null;
            }

            logger.debug("Found HTMLTextAreaElement: name=" + textAreaElement.getName());

            onHTMLTextAreaElement((HTMLTextAreaElement) node);
        }

        return null;
    }

    public final void onHTMLFormElement(HTMLFormElement element) {
        contentHandler.onHTMLForm(element.getId(), element.getName());
    }

    public final void onHTMLInputElement(HTMLInputElement element) {
        String name = element.getName();
        if (contentHandler.isElementExcluded(name)) {
            logger.debug("Skipping excluded HtmlInputElement: name=" + element.getName());

            return;
        }

        String type = element.getType();

        if ("button".equals(type)) {
            onHTMLInputButtonElement(element);
        } else
        if ("checkbox".equals(type)) {
            onHTMLInputCheckboxElement(element);
        } else
        if ("text".equals(type)) {
            onHTMLInputTextElement(element);
        } else
        if ("password".equals(type)) {
            onHTMLInputPasswordElement(element);
        } else
        if ("submit".equals(type)) {
            onHTMLInputSubmitElement(element);
        } else
        if ("file".equals(type)) {
            onHTMLInputFileElement(element);
        } else
        if ("radio".equals(type)) {
            onHTMLInputRadioElement(element);
        } else
        if ("hidden".equals(type)) {
            onHTMLInputHiddenElement(element);
        }
    }

    public final void onHTMLInputButtonElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();

        contentHandler.onHTMLInputButton(name, value);
    }

    public final void onHTMLInputCheckboxElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();
        boolean checked = element.getChecked();

        contentHandler.onHTMLInputCheckbox(name, value, checked);
    }

    public final void onHTMLInputFileElement(HTMLInputElement element) {
        String name = element.getName();
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
            String hashValue = HexStringHelper.toHexString(digestBytes);

            contentHandler.onHTMLInputFile(name, filename, hashValue);
        } catch (FileNotFoundException e) {
            logger.warn("File not found: " + filename, e);
        } catch (IOException e) {
            logger.warn("I/O error: " + filename, e);
        } catch (NoSuchAlgorithmException e) {
            logger.warn("No such algorithm exception", e);
        } catch (Exception e) {
            logger.warn("Unhandled exception", e);
        }
    }

    public void onHTMLInputPasswordElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();

        contentHandler.onHTMLInputPassword(name, value);
    }

    public final void onHTMLInputRadioElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();
        boolean checked = element.getChecked();

        contentHandler.onHTMLInputRadio(name, value, checked);
    }

    public final void onHTMLInputSubmitElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();

        contentHandler.onHTMLInputSubmit(name, value);
    }

    public final void onHTMLInputTextElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();

        contentHandler.onHTMLInputText(name, value);
    }

    public final void onHTMLInputHiddenElement(HTMLInputElement element) {
        String name = element.getName();
        String value = element.getValue();

        contentHandler.onHTMLInputHidden(name, value);
    }

    public final void onHTMLSelectElement(HTMLSelectElement element) {
        String name = element.getName();
        if (contentHandler.isElementExcluded(name)) {
            return;
        }

        Object selectObject = contentHandler.onHTMLSelect(
                name,
                element.getMultiple());

        HTMLCollection options = element.getOptions();
        if (options != null) {
            for (int i=0; i<options.getLength(); i++) {
                HTMLOptionElement optionElement = (HTMLOptionElement) options.item(i);
                onHTMLOptionElement(optionElement, selectObject);
            }
        } else {
            // Fallback to looking for child nodes named 'option'; it seems
            // some browsers fail to return the OPTION elements using
            // HTMLSelectElement.getOptions()
            NodeList nl = element.getChildNodes();
            for (int i=0; i<nl.getLength(); i++) {
                Node node = nl.item(i);
                if (    node.getNodeType() == Node.ELEMENT_NODE &&
                        node.getNodeName().equalsIgnoreCase("option")) {
                    onHTMLOptionElement((HTMLOptionElement) node, selectObject);
                }
            }
        }
    }

    public final void onHTMLOptionElement(HTMLOptionElement element, Object selectObject) {
        String value = element.getValue();
        boolean selected = element.getSelected();
        String text = element.getText();

        contentHandler.onHTMLOption(value, selected, text, selectObject);
    }

    public final void onHTMLTextAreaElement(HTMLTextAreaElement element) {
        String name = element.getName();
        if (contentHandler.isElementExcluded(name)) {
            return;
        }

        String value = element.getValue();

        contentHandler.onHTMLTextArea(name, value);
    }

}
