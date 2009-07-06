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

package net.sf.dsig;

import java.awt.Color;
import java.awt.Dialog.ModalityType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
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

import net.sf.dsig.helpers.KeyStoreHelper;
import net.sf.dsig.helpers.KeyUsageHelper;
import net.sf.dsig.helpers.UserHomeSettingsParser;
import net.sf.dsig.impl.StaticStrategyFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.java.browser.dom.DOMService;

/**
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class DSApplet extends JApplet {

	private static final long serialVersionUID = -7671795492911882803L;

	private static final Log logger = LogFactory.getLog(DSApplet.class);
	
	private static final String DSAPPLET_VERSION = "2.0-SNAPSHOT";
	
	/**
	 * The background color of the applet
	 */
	private String backgroundColor = "#FFFFFF";
	
	public void setBackgroundColor(String backgroundColor) {
		this.backgroundColor = backgroundColor;
	}
	
	/**
	 * The id of the form to sign; if set, applet will render itself as a
	 * button, that will submit the form with the corresponding id.
	 */
	private String formId = null;
	
	public void setFormId(String formId) {
		if (formId == null || formId.length() == 0) {
			this.formId = null;
		} else {
			this.formId = formId;
		}
	}
	
	/**
	 * <p>The name of the JavaScript function to invoke on successful completion
	 * of the digital signing process.
	 * 
	 * <p>The method is called as follows:
	 * <pre><i>successJSFunction();
	 */
	private String successJSFunction = null;
	
	public void setSuccessJSFunction(String successJSFunction) {
		this.successJSFunction = successJSFunction;
	}
	
	/**
	 * <p>The name of the JavaScript function to invoke when an error occurs
	 * during the digital signing process.
	 * 
	 * <p>The method is called as follows:
	 * <pre><i>errorJSFunction(errorCode);
	 */
	private String errorJSFunction = null;
	
	public void setErrorJSFunction(String errorJSFunction) {
		this.errorJSFunction = errorJSFunction;
	}
	
	/**
	 * <p>A regular expression that is tested against the subject of the
	 * certificate. When set only matching certificates are accepted
	 * and displayed for selection.
	 */
	private String subjectMatchingRegex = null;
	
	public void setSubjectMatchingRegex(String subjectRegex) {
		this.subjectMatchingRegex = subjectRegex;
	}
	
	private Pattern subjectMatchingPattern = null;
	
	private Pattern getSubjectMatchingPattern() {
		if (subjectMatchingPattern == null && subjectMatchingRegex != null) {
			subjectMatchingPattern = Pattern.compile(subjectMatchingRegex);
		}
		
		return subjectMatchingPattern;
	}
	
	/**
	 * <p>A regular expression that is tested against the issuer
	 * of the certificate. When set only matching certificates are accepted
	 * and displayed for selection. 
	 */
	private String issuerMatchingRegex = null;
	
	public void setIssuerMatchingRegex(String issuerMatchingRegex) {
		this.issuerMatchingRegex = issuerMatchingRegex;
	}
	
	private Pattern issuerMatchingPattern = null;
	
	private Pattern getIssuerMatchingPattern() {
		if (issuerMatchingPattern == null && issuerMatchingRegex != null) {
			issuerMatchingPattern = Pattern.compile(issuerMatchingRegex);
		}
		
		return issuerMatchingPattern;
	}
	
	/**
	 * A comma-separated list of serial numbers, for testing against each
	 * certificate's serial number. When set only matching certificates are
	 * accepted and displayed for selection.
	 */
	private String serialNumbersAllowed = null;
	
	public void setSerialNumbersAllowed(String serialNumbersAllowed) {
		this.serialNumbersAllowed = serialNumbersAllowed;
	}
	
	private Set<BigInteger> serialNumbersAllowedSet = null;

	public Set<BigInteger> getSerialNumbersAllowedSet() {
		if (	serialNumbersAllowedSet == null &&
				serialNumbersAllowed != null) {
			String[] serialNumbers = serialNumbersAllowed.split(",");
			serialNumbersAllowedSet = new HashSet<BigInteger>();
			for (String serialNumber: serialNumbers) {
				serialNumbersAllowedSet.add(new BigInteger(serialNumber));
			}
		}
		
		return serialNumbersAllowedSet;
	}

	/** Flag controlling whether the expiration date is checked */
	private boolean expirationDateChecked = true;
	
	public void setExpirationDateChecked(boolean expirationDateChecked) {
		this.expirationDateChecked = expirationDateChecked;
	}
	
	/** A comma-separated list of KeyUsage attributes to check. When set
	 * only certificates containing all of the required attributes will be
	 * accepted and displayed for selection.
	 */
	private String keyUsageRestrictions = null;

	public void setKeyUsageRestrictions(String keyUsageRestrictions) {
		this.keyUsageRestrictions = keyUsageRestrictions;
	}
	
	/** Flag controlling whether the status bar message is shown */
	private boolean statusBarMessageShown = true;
	
	public void setStatusBarMessageShown(boolean statusBarMessageShown) {
		this.statusBarMessageShown = statusBarMessageShown;
	}
	
	@Override
	public String[][] getParameterInfo() {
		return new String[][] {
				{ 	"backgroundColor", "String", 
					"background color code, in hexadecimal format; defaults to white (#FFFFFF)" },
				{ 	"formId", "String", 
					"id of the HTML form to digitally sign" },
				{ 	"successJSFunction", "String", 
					"name of JS function to execute on succesful signing; called with no arguments (i.e. onSuccess(); )" },
				{ 	"errorJSFunction", "String", 
					"name of JS function to execute on failed signing; called with no arguments (i.e. onError(); )" },
				{ 	"issuerNameRegex", "String", 
					"regular expression to match issuer's name for acceptance" },
				{ 	"subjectNameRegex", "String", 
					"regular expression to match certificate's name in subject" },
				{ 	"subjectFriendlyRegex", "String", 
					"regular expression to match certificate's friendly name in subject" },
				{ 	"serialNumbersAllowed", "String, comma-delimited", 
					"list of serial numbers to allow for selection" },
				{ 	"expirationDateChecked", "boolean", 
					"true to check certificate's expiration date (default); false otherwise" },
				{ 	"keyUsageRestrictions", "String", 
					"list of required key usage purposes" },
				{	"statusBarMessageShown", "String",
					"true to display in the status bar the version message (default); false otherwise" },
		};
	}
	
	// Only lookup .properties files
	private ResourceBundle messages = ResourceBundle.getBundle("messages",
			ResourceBundle.Control.getControl(ResourceBundle.Control.FORMAT_PROPERTIES));
	
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
	
	private StrategyFactory strategyFactory = StaticStrategyFactory.getSingleton();
	
	@Override
	public void init() {
		super.init();
		
		// Environment initialization --------------------------------------- //
		Environment.getSingleton().setApplet(this);
		Environment.getSingleton().setProperties(
				UserHomeSettingsParser.parse());
		
		// Set the default java.logging logger for FINEST logging on
		// gr.ageorgiadis package when debug environmental parameter is set
		if (Boolean.parseBoolean(Environment.getSingleton().getValue("debug"))) {
			System.out.println("\n*** Debug log enabled ***");
			
			Logger.getLogger("").getHandlers()[0].setLevel(Level.FINEST);
			Logger.getLogger("").setLevel(Level.INFO);
			
			Logger.getLogger("net.sf.dsig").setLevel(Level.FINEST);
		}

		// Applet initialization through the Environment class -------------- //
		Environment.getSingleton().init(this);
		
		// LiveConnect proxy initialization --------------------------------- //
		LiveConnectProxy.getSingleton().setApplet(this);
		
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
	}
	
	@Override
	public void start() {
		// Add a small delay before printing the status; otherwise it will
		// be overridden by the '..Applet started' Plug-In message
		if (statusBarMessageShown) {
			new Thread(new Runnable() {
				@Override
				public void run() {
					try { Thread.sleep(500); } catch (InterruptedException e) { }
					showStatus("Digital Signature Applet - " +
							DSAPPLET_VERSION);
				}
			}).start();
		}
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
	
	public boolean signInternal(String formId) {
		KeyStoreFactory ksf = KeyStoreFactory.createKeyStoreFactoryChain();
		KeyStore ks = null;
		KeyStoreHelper ksh = null;
		try {
			ks = ksf.getKeyStore();
			ksh = new KeyStoreHelper(ks);

			logger.debug("KeyStore object created; provider.name=" + ks.getProvider().getName());
		} catch (Exception e) {
			handleError("DSA0001", e);
		}
		
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = 
				new HashMap<String, X509Certificate[]>();

		try {
			Set<String> aliases = ksh.aliases();
			for (String alias : aliases) {
				X509Certificate[] certificateChain = ksh.getX509CertificateChain(alias);
				if (certificateChain == null || certificateChain.length == 0) {
					logger.warn("Null certificate chain returned; alias=" + alias);
					
					continue;
				}
				
				X509Certificate certificate = certificateChain[0];
				
				String subjectName = certificate.getSubjectX500Principal().getName();
				String issuerName = certificate.getIssuerX500Principal().getName();
				BigInteger serialNumber = certificate.getSerialNumber();
	
				// Filter by subject
				
				if (	getSubjectMatchingPattern() != null &&
						!getSubjectMatchingPattern().matcher(subjectName).matches()) {
					logger.info("Subject does not match; skipping" +
							": certificate.subject=" + subjectName);
					continue;
				}
				
				// Filter by issuer
				
				if (	getIssuerMatchingPattern() != null &&
						!getIssuerMatchingPattern().matcher(issuerName).matches()) {
					logger.info("Issuer does not match; skipping" +
							": certificate.subject=" + subjectName +
							", certificate.issuer=" + issuerName);
					continue;
				}
				
				// Filter by serial number
				
				if (	getSerialNumbersAllowedSet() != null &&
						!getSerialNumbersAllowedSet().contains(serialNumber)) {
					logger.info("Serial number is not allowed; skipping" + 
							": certificate.subject=" + subjectName +
							", certificate.serialNumber=" + serialNumber);
					continue;
				}
				
				// Filter by key usage
				
				if (	keyUsageRestrictions != null &&
						!KeyUsageHelper.validateKeyUsage(certificate, keyUsageRestrictions)) {
					logger.info("Key usage restrictions not met; skipping" + 
							": certificate.subject=" + subjectName +
							", certificate.keyUsage=" + KeyUsageHelper.printKeyUsage(certificate));
					continue;
				}
				
				// Filter by private key
				
				if (!ksh.isKeyEntry(alias)) {
					logger.info("Private key not found; skipping" + 
							": certificate.subject=" + subjectName);
					continue;
				}
				
				logger.debug("Accepting certificate" + 
						"; certificate.subject=" + subjectName +
						", certificate.serialNumber=" + serialNumber);
				
				aliasX509CertificateChainPair.put(alias, ksh.getX509CertificateChain(alias));
			}
		} catch (Exception e) {
			handleError("DSA0002", e);
		}
		
		CertificateTableModel ctm = new CertificateTableModel(
					aliasX509CertificateChainPair,
					messages);
		Environment.getSingleton().init(ctm);
		
		SelectCertificateDialog scd = new SelectCertificateDialog(
				ctm,
				ks.getProvider().getName(),
				expirationDateChecked,
				messages);
		
		scd.setModalityType(ModalityType.APPLICATION_MODAL);
		scd.setVisible(true);

		String alias = scd.getSelectedAlias();
		if (alias == null) {
			return false;
		}

		PrivateKey privateKey = null;
		try {
			privateKey = ksh.getPrivateKey(alias, null);
		} catch (Exception e) {
			handleError("DSA0003", e);
		}

		X509Certificate[] certificateChain = null;
		try {
			certificateChain = ksh.getX509CertificateChain(alias);
		} catch (Exception e) {
			handleError("DSA0004", e);
		}
		
		Strategy strategy = strategyFactory.getStrategy();
		
		FormParser parser = new FormParser(this, formId);
		parser.setContentHandler(
				strategy.getFormContentHandler());
		try {
			DOMService.getService(this).invokeAndWait(parser.getParsingDOMAction());
		} catch (Exception e) {
			handleError("DSA0005", e);
		}
		
		try {
			strategy.sign(privateKey, certificateChain);
		} catch (Exception e) {
			handleError("DSA0006", e);
		}
		
		if (successJSFunction != null) {
			LiveConnectProxy.getSingleton().eval(successJSFunction + "();");
		} else {
			logger.debug("successJSFunction not set");
		}
		
		return true;
	}
	
	@Override
	public String getAppletInfo() {
		return "Digital Signature Applet - " +
			DSAPPLET_VERSION +
			"\nCopyright \u00a9 2007-2009 Anestis Georgiadis" +
			"\nhttp://dsig.sourceforge.net";
	}
	
	private String printInfoMessage() {
		StringBuilder sb = new StringBuilder();
		sb.append(getAppletInfo());
		sb.append("\n\n");
		
		sb.append("Strategy: " + strategyFactory.getName() + "\n");

		return sb.toString();
	}
	
	private void handleError(String errorCode, Throwable cause) {
		ErrorDialog ed = new ErrorDialog(errorCode, cause, messages);
		ed.setModalityType(ModalityType.APPLICATION_MODAL);
		ed.setVisible(true);
		
		if (errorJSFunction != null) {
			LiveConnectProxy.getSingleton().eval(
					errorJSFunction + "(" + errorCode + ");");
		} else {
			if (cause instanceof RuntimeException) {
				throw (RuntimeException) cause;
			} else {
				throw new RuntimeException(cause);
			}
		}
	}
	

}
