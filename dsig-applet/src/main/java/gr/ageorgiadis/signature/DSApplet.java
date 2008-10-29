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

import gr.ageorgiadis.security.BrowserKeyStoreFactory;
import gr.ageorgiadis.security.KeyStoreHelper;
import gr.ageorgiadis.util.AppletInitHelper;
import gr.ageorgiadis.util.HexStringHelper;
import gr.ageorgiadis.util.ini.Parser.MalformedException;

import java.awt.Color;
import java.awt.Dialog.ModalityType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import netscape.javascript.JSException;
import netscape.javascript.JSObject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.java.browser.dom.DOMAccessException;
import com.sun.java.browser.dom.DOMService;
import com.sun.java.browser.dom.DOMUnsupportedException;

public class DSApplet extends JApplet {
	
	private static final Log logger = LogFactory.getLog(DSApplet.class);

	private static final long serialVersionUID = 3617857231362031733L;

	private String backgroundColor = "#FFFFFF";
	
	/**
	 * Set the root panel's background color 
	 * 
	 * @param backgroundColor the color code, in hexadecimal format; defaults to
	 * #FFFFFF (white) if not explicitly set
	 */
	public void setBackgroundColor(String backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	private String formId = null;
	
	/**
	 * Set the id of the form for which the digital signature algorithm will
	 * be executed
	 * 
	 * @param formId the id of the HTML form element, to be looked up via
	 * DOM's window.getElementById() method.
	 */
	public void setFormId(String formId) {
		this.formId = formId;
	}

	private String flags = null;
	
	/**
	 * Set a comma-delimited list of flags, that will be passed to the 
	 * selected SignatureStrategy
	 */
	public void setFlags(String flags) {
		this.flags = flags;
	}

	private String signatureAlgorithm = "xmldsig";
	
	/**
	 * Set the name of SignatureStrategy. Supported values  
	 * are <code>debug</code>, <code>nameValue</code> and<code>xmldsig</code>,
	 * as well as the standard signing algorithms of Java.
	 */
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	
	private String signatureElement;
	
	public String getSignatureElement() {
		return signatureElement;
	}
	
	/**
	 * Set the name of the input element where the signature will be stored, as
	 * soon as the signing algorithm completes.
	 */
	public void setSignatureElement(String signatureElement) {
		this.signatureElement = signatureElement;
	}
	
	private String plaintextElement;
	
	public String getPlaintextElement() {
		return plaintextElement;
	}
	
	/**
	 * Set the name of the input element where the plaintext will be stored. 
	 */
	public void setPlaintextElement(String plaintextElement) {
		this.plaintextElement = plaintextElement;
	}
	
	private String serialNumberElement;
	
	public String getSerialNumberElement() {
		return serialNumberElement;
	}
	
	/**
	 * Set the name of the input element where the serial number of the
	 * certificate used will be stored. 
	 */
	public void setSerialNumberElement(String serialNumberElement) {
		this.serialNumberElement = serialNumberElement;
	}
	
	private boolean serialNumberInHexadecimal = false;
	
	public void setSerialNumberInHexadecimal(boolean serialNumberInHexadecimal) {
		this.serialNumberInHexadecimal = serialNumberInHexadecimal;
	}
	
	private String excludedElements = null;
	
	/**
	 * Set the semicolon-separated list of elements to ignored
	 * @param ignoredElements
	 */
	public void setExcludedElements(String excludedElements) {
		this.excludedElements = excludedElements;
	}
	
	private String includedElements = null;
	
	public void setIncludedElements(String includedElements) {
		this.includedElements = includedElements;
	}
	
	private Set<String> excludedElementsSet = null;
	
	private Set<String> includedElementsSet = null;

	public boolean isElementExcluded(String element) {
		if (excludedElementsSet == null) {
			excludedElementsSet = new HashSet<String>();
			
			if (excludedElements != null) {
				String[] names = excludedElements.split(";");
				for (String name : names) {
					excludedElementsSet.add(name.trim());
				}
			}
		}
		
		if (includedElementsSet == null) {
			includedElementsSet = new HashSet<String>();
			
			if (includedElements != null) {
				String[] names = includedElements.split(";");
				for (String name: names) {
					includedElementsSet.add(name.trim());
				}
			}
		}
		
		return excludedElementsSet.contains(element) ||
			(	!includedElementsSet.isEmpty() && 
				!includedElementsSet.contains(element));
	}
	
	private String successJSFunction = null;
	
	public String getSuccessJSFunction() {
		return successJSFunction;
	}
	
	/**
	 * <p>Set the name of the JavaScript function to execute if the signing
	 * process executes successfully. This function will be called with no
	 * arguments, e.g.:</p>
	 * <code>onSuccess();</code>   
	 */
	public void setSuccessJSFunction(String submitFunction) {
		this.successJSFunction = submitFunction;
	}
	
	private String errorJSFunction = null;
	
	public String getErrorJSFunction() {
		return errorJSFunction;
	}
	
	/**
	 * <p>Set the name of the JavaScript function to execute if an error occurs
	 * during the signing process. This function will be called with a String
	 * argument, the error code. E.g.:</p>
	 * <code>onError(errorCode);</code>   
	 */
	public void setErrorJSFunction(String errorFunction) {
		this.errorJSFunction = errorFunction;
	}
	
	private boolean expirationDateChecked = true;

	public boolean isExpirationDateChecked() {
		return expirationDateChecked;
	}
	
	public void setExpirationDateChecked(boolean expirationDateChecked) {
		this.expirationDateChecked = expirationDateChecked;
	}
	
	private String issuerNameRegex = null;
	
	public String getIssuerNameRegex() {
		return issuerNameRegex;
	}
	
	public void setIssuerNameRegex(String issuerNameRegex) {
		this.issuerNameRegex = issuerNameRegex;
	}
	
	private Pattern issuerNamePattern = null;
	
	public Pattern getIssuerNamePattern() {
		return issuerNamePattern;
	}
	
	public void setIssuerNamePattern(Pattern issuerNamePattern) {
		this.issuerNamePattern = issuerNamePattern;
	}
	
	private ResourceBundle messages = ResourceBundle.getBundle("messages");
	private ResourceBundle application = ResourceBundle.getBundle("application");
	
	@Override
	public String getAppletInfo() {
		return "Digital Signature Applet - " +
			application.getString("dsig-applet.version") +
			"\nhttp://dsig.sourceforge.net";
	}
	
	private UserAgentHelper userAgentHelper = new UserAgentHelper();
	
	private void initSwing() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Exception e) {
			logger.warn("UIManager.setLookAndFeel() failed", e);
		}
		
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.LINE_AXIS));
		panel.setBackground(Color.decode(backgroundColor));
		add(panel);	
		
		boolean lockPrinted = false;
		if (formId != null) {
			Icon lockIcon = new ImageIcon(getClass().getResource("/icons/lock.png"));
			lockPrinted = true;
			
			JButton button = new JButton("Sign", lockIcon);
			button.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					try {
						signInternal(formId);
					} catch (Exception ex) { }
				}
			});
			panel.add(button);
		}
		
		Icon infoIcon = new ImageIcon(getClass().getResource(
				lockPrinted?"/icons/info.png":"/icons/lock.png"));
		JLabel infoLabel = new JLabel(infoIcon);
		infoLabel.addMouseListener(new MouseListener() {
			public void mouseClicked(MouseEvent e) {
				JOptionPane.showMessageDialog(null, printInfoMessage());
			}
			public void mouseEntered(MouseEvent e) { /* NOOP */ }
			public void mouseExited(MouseEvent e) { /* NOOP */ }
			public void mousePressed(MouseEvent e) { /* NOOP */ }
			public void mouseReleased(MouseEvent e) { /* NOOP */ }
		});
		panel.add(infoLabel);
	}
	
	@Override
	public void init() {
		super.init();

		// Set the default java.logging logger for FINEST logging on
		// gr.ageorgiadis package when debug system property is set
		if (Boolean.getBoolean("debug")) {
			System.out.println("\n*** Debug log enabled ***");
			
			Logger.getLogger("").getHandlers()[0].setLevel(Level.FINEST);
			Logger.getLogger("").setLevel(Level.INFO);
			
			Logger.getLogger("gr.ageorgiadis").setLevel(Level.FINEST);
		}
		
		// Applet initialization through the AppletInitHelper auxiliary class //
		AppletInitHelper.init(this);
		
		// Swing initialization --------------------------------------------- //
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					initSwing();
				}
			});
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			userAgentHelper.initialize(JSObject.getWindow(DSApplet.this));
		} catch (JSException e) { 
			e.printStackTrace();
		}
		
		// IssuerName regex initialization ---------------------------------- //
		if (getIssuerNameRegex() != null) {
			setIssuerNamePattern(Pattern.compile(getIssuerNameRegex()));
		}
	}
	
	@Override
	public void start() {
		// Add a small delay before printing the status; otherwise it will
		// be overriden by the '..Applet started' Plug-In message
		new Thread(new Runnable() {
			@Override
			public void run() {
				try { Thread.sleep(500); } catch (InterruptedException e) { }
				showStatus("Digital Signature Applet - " +
						application.getString("dsig-applet.version"));
			}
		}).start();
	}
	
	public boolean sign(final String formId) {
		try {
			// Run the signing process in the Event-Dispatch thread of Swing
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					if (!signInternal(formId)) {
						throw new RuntimeException("So that catch() below is invoked");
					}
				}
			});
			return true;
		} catch (Exception e) {
			return false;
		}	
	}
	
	private boolean signInternal(final String formId) throws RuntimeException {
		try {
			final KeyStoreHelper ksh;
			final Map<String, X509Certificate[]> aliasX509CertificateChainPair = 
					new HashMap<String, X509Certificate[]>();

			final KeyStore ks = 
				BrowserKeyStoreFactory.getInstance().createKeyStore(userAgentHelper);
			
			ksh = new KeyStoreHelper(ks);

			Set<String> aliases = ksh.aliases();
			for (String alias : aliases) {
				X509Certificate certificate = ksh.getX509CertificateChain(alias)[0];
				String subjectName = certificate.getSubjectX500Principal().getName();
				
				String issuerName = certificate.getIssuerX500Principal().getName();
				if (	issuerNamePattern != null &&
						!issuerNamePattern.matcher(issuerName).matches()) {
					logger.info("Issuer does not match; skipping" +
							": subject.name=" + subjectName);
					continue;
				}
				
				if (!ksh.isKeyEntry(alias)) {
					continue;
				}
				
				aliasX509CertificateChainPair.put(alias, ksh.getX509CertificateChain(alias));
			}

			SelectCertificateDialog scd = new SelectCertificateDialog(
					new CertificateTableModel(aliasX509CertificateChainPair),
					ks.getProvider().getName(),
					isExpirationDateChecked());
			
			scd.setModalityType(ModalityType.APPLICATION_MODAL);
			scd.setVisible(true);
			
			String alias = scd.getSelectedAlias();
			if (alias == null) {
				return false;
			}

			SignatureStrategy strategy = SignatureStrategy.getInstance(signatureAlgorithm);
			strategy.setFlags(flags);
			strategy.setPrivateKey(ksh.getPrivateKey(alias, null));
			strategy.setX509Certificate(scd.getSelectedX509Certificate());
			
			FormParser parser = new FormParser(this, formId);
			parser.setElementHandler(strategy.getElementHandler());

			DOMService.getService(this).invokeAndWait(parser.getParsingDOMAction());
			
			JSObject win = JSObject.getWindow(DSApplet.this);
			
			if (getPlaintextElement() != null) {
				String command = getDOMExpression(formId, getPlaintextElement()) + 
						".value = \"" + 
						strategy.getPlaintext() + "\";";

				win.eval(command);
			} else {
				logger.warn("plaintextElement not set");
			}
			
			String serialNumberAsString = serialNumberInHexadecimal ?
					HexStringHelper.toHexString(scd.getSelectedX509Certificate().getSerialNumber().toByteArray()) :
					"" + scd.getSelectedX509Certificate().getSerialNumber();
			if (getSerialNumberElement() != null) {
				String command = getDOMExpression(formId, getSerialNumberElement()) + ".value = '" + 
						serialNumberAsString + "';";

				win.eval(command);
			} else {
				logger.warn("serialNumberElement not set");
			}
			if (getSignatureElement() != null) {
				String command = getDOMExpression(formId, getSignatureElement()) + ".value = '" + 
						strategy.getSignature() + "';";

				win.eval(command);
			} else {
				logger.warn("signatureElement not set");
			}
			
			if (getSuccessJSFunction() != null) {
				win.eval(getSuccessJSFunction() + "();");
			} else {
				logger.debug("successJSFunction not set");
			}
			
			return true;
		} catch (KeyStoreException ex) {
			handleError("DSA0001", ex);
		} catch (NoSuchProviderException ex) {
			handleError("DSA0002", ex);
		} catch (NoSuchAlgorithmException ex) {
			handleError("DSA0003", ex);
		} catch (CertificateException ex) {
			handleError("DSA0004", ex);
		} catch (IOException ex) {
			handleError("DSA0005", ex);
		} catch (IllegalArgumentException ex) {
			handleError("DSA0006", ex);
		} catch (IllegalAccessException ex) {
			handleError("DSA0006", ex);
		} catch (UnrecoverableKeyException ex) {
			handleError("DSA0007", ex);
		} catch (DOMUnsupportedException ex) {
			handleError("DSA0008", ex);
		} catch (DOMAccessException ex) {
			handleError("DSA0009", ex);
		} catch (SignatureException ex) {
			handleError(ex.getErrorCode(), ex.getCause());
		} catch (MalformedException ex) {
			handleError("DSA9999", ex);
		} catch (RuntimeException ex) {
			handleError("DSA9999", ex);
		}
		
		return false;
	}
	
	private String printInfoMessage() {
		StringBuilder sb = new StringBuilder();
		sb.append(getAppletInfo());
		sb.append("\n\n");
		
		sb.append(System.getProperty("java.vm.name") + "; " + System.getProperty("java.vm.version") + ", " + System.getProperty("java.vm.vendor") + "\n");

		sb.append("\nOS detected: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " ("+ System.getProperty("os.version") + ")\n");
		sb.append("Browser detected: " + userAgentHelper.getBrowser() + "\n");
		sb.append("Security Provider: " + BrowserKeyStoreFactory.getInstance().getProviderName(userAgentHelper) + "\n");
		sb.append("Signature Strategy: " + signatureAlgorithm + "\n");
		sb.append("\nIcons provided by: FAMFAMFAM\n");

		return sb.toString();
	}
	
	private String getDOMExpression(String formId, String element) {
		return "document.forms[\"" + formId + "\"].elements[\"" + element + "\"]";
	}
	
	private void handleError(String errorCode, Throwable cause) {
		ErrorDialog ed = new ErrorDialog(errorCode, cause, messages);
		ed.setModalityType(ModalityType.APPLICATION_MODAL);
		ed.setVisible(true);
		
		JSObject win = JSObject.getWindow(DSApplet.this);
		if (getErrorJSFunction() != null) {
			win.eval(getErrorJSFunction() + "(" + errorCode + ");");
		} else {
			if (cause instanceof RuntimeException) {
				throw (RuntimeException) cause;
			} else {
				throw new RuntimeException(cause);
			}
		}
	}
	
}
