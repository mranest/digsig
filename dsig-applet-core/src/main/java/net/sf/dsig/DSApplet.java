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

import java.awt.Color;
import java.awt.Dialog.ModalityType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Date;
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

import net.sf.dsig.helpers.KeyUsageHelper;
import net.sf.dsig.helpers.UserHomeSettingsParser;
import net.sf.dsig.impl.StaticStrategyFactory;
import net.sf.dsig.keystores.KeyStoreProxy;
import net.sf.dsig.keystores.KeyStoreProxyFactory;

import org.apache.commons.lang.StringEscapeUtils;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.Profiler;

import com.sun.java.browser.dom.DOMService;

public class DSApplet extends JApplet {

	private static final long serialVersionUID = -7671795492911882803L;

	private static final org.slf4j.Logger logger = 
			LoggerFactory.getLogger(DSApplet.class);
	
	private static final String DSAPPLET_VERSION = "2.2.0-20110216";
	
	private static final Profiler initProfiler = new Profiler("INITIALIZATION");
	
	static {
		initProfiler.start("Initializing");
	}
	
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
	 * <p>The name of the JavaScript function to invoke when no certificates
	 * are available for performing a digital signature.
	 * 
	 * <p>The method is called as follows:
	 * <pre><i>noCertificatesJSFunction();
	 */
	private String noCertificatesJSFunction = null;
	
	public void setNoCertificatesJSFunction(String noCertificatesJSFunction) {
		this.noCertificatesJSFunction = noCertificatesJSFunction;
	}
	
	/**
	 * <p>The name of the JavaScript function to invoke when the applet
	 * has started.
	 * 
	 * <p>The method is called as follows:
	 * <pre><i>startedJSFunction();
	 */
	private String startedJSFunction = null;
	
	public void setStartedJSFunction(String startedJSFunction) {
		this.startedJSFunction = startedJSFunction;
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
	
	private String userAgent;
	
	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}
	
	public String getUserAgent() {
		return userAgent;
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
				{ 	"noCertificatesJSFunction", "String", 
					"name of JS function to execute when no certificates exist; called with no arguments (i.e. onNoCertificates(); )" },
				{ 	"startedJSFunction", "String", 
					"name of JS function to execute when applet has started; called with no arguments (i.e. onNoCertificates(); )" },
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
				{	"userAgent", "String",
					"Enclosing browser's user agent" },
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
						signInternal(formId, null);
					} catch (Exception ex) { 
						logger.error("Internal sign failed", e);
					}
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
	
	private KeyStoreProxy keyStoreProxy = null;
	private Exception createKeyStoreProxyException = null;
	
	private KeyStoreProxy getKeyStoreProxy() {
		if (createKeyStoreProxyException != null) {
			handleError("DSA0001", createKeyStoreProxyException);
		}
		
		return keyStoreProxy;
	}
	
	@Override
	public void init() {
		super.init();
		
		// Environment initialization --------------------------------------- //
		initProfiler.start("Environment init");
		Environment.getSingleton().setApplet(this);
		Environment.getSingleton().setProperties(
				UserHomeSettingsParser.parse());
		
		// Set the default java.logging logger for FINEST logging on
		// gr.ageorgiadis package when debug environmental parameter is set
		initProfiler.start("Logging init");
		if (Boolean.parseBoolean(Environment.getSingleton().getValue("debug"))) {
			System.out.println("\n*** Debug log enabled ***");
			
			Logger.getLogger("").getHandlers()[0].setLevel(Level.FINEST);
			Logger.getLogger("").setLevel(Level.INFO);
			
			Logger.getLogger("net.sf.dsig").setLevel(Level.FINEST);
		}

		// Applet initialization through the Environment class -------------- //
		initProfiler.start("Applet init");
		Environment.getSingleton().init(this);
		
		// LiveConnect proxy initialization --------------------------------- //
		LiveConnectProxy.getSingleton().setApplet(this);
		
		// KeyStoreProxy initialization ------------------------------------- //
		try {
			KeyStoreProxyFactory factory = new KeyStoreProxyFactory();
			Environment.getSingleton().init(factory);
			
			keyStoreProxy = factory.createKeyStoreProxy();
		} catch (Exception e) {
			logger.error("Error while creating keyStoreProxy", e);
			
			createKeyStoreProxyException = e;
		}
		
		// Swing initialization --------------------------------------------- //
		initProfiler.start("Swing init");
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					initSwing();
				}
			});
		} catch (Exception e) {
			logger.error("Swing initialization failed", e);
		}

		initProfiler.start("Starting");
	}
	
	private boolean started = false;
	
	@Override
	public void start() {
		// Add a small delay before performing the started operations (in
		// the case of status printing it will otherwise be overridden by 
		// the '..Applet started' Plug-In message)
		new Thread(new Runnable() {
			@Override
			public void run() {
				try { Thread.sleep(500); } catch (InterruptedException e) { }
				
				if (statusBarMessageShown) {
					showStatus("Digital Signature Applet - " +
							DSAPPLET_VERSION);
				}
				
				if (startedJSFunction != null) {
					LiveConnectProxy.getSingleton().eval(startedJSFunction + "();");
				}
			}
		}).start();
		
		started = true;
		
		initProfiler.setLogger(logger);
		
		initProfiler.stop().log();
	}

	/**
	 * Sign a form using a certificate selected from a dialog box
	 * @param formId the id of the form to lookup through DOM traversal
	 * @return true if signing has completed successfully, false otherwise
	 * @category JavaScript exposed method
	 */
	public boolean sign(final String formId) {
		return sign(formId, null);
	}
	
	/**
	 * Sign a form using the certificate with the supplied alias
	 * @param formId the id of the form to lookup through DOM traversal
	 * @param alias the alias of the selected certificate
	 * @return true if signing has completed successfully, false otherwise
	 * @category JavaScript exposed method
	 * @since 2.1.0
	 */
	public boolean sign(final String formId, final String alias) {
		if (alias != null) {
			return signInternal(formId, alias);
		}
		
		// Null alias means the certificate selection dialog box will pop-up; 
		// hence, we need to be running in Swing's event dispatch thread

		class SignInternalRunnable implements Runnable {
			private boolean successful;
			public boolean isSuccessful() {
				return successful;
			}
			@Override
			public void run() {
				successful = signInternal(formId, alias);
			}
		}
		SignInternalRunnable sir = new SignInternalRunnable();
		
		try {
			SwingUtilities.invokeAndWait(sir);
			
			return sir.isSuccessful();
		} catch (Exception e) {
			logger.error("Internal sign failed", e);
			
			return false;
		}
	}
	
	/**
	 * Sign the supplied plaintext using the certificate with the supplied alias
	 * @param plaintext the plaintext to sign
	 * @param alias the alias of the selected certificate
	 * @return a jsonResponse containing the signature
	 * @since 2.2.0
	 * @category JavaScript exposed method
	 */
	public String signPlaintext(final String plaintext, final String alias) {
		if (alias != null) {
			return signPlaintextInternal(plaintext, alias);
		}

		// Null alias means the certificate selection dialog box will pop-up; 
		// hence, we need to be running in Swing's event dispatch thread
		
		class SignPlaintextInternalRunnable implements Runnable {
			private String jsonResponse;
			public String getJsonResponse() {
				return jsonResponse;
			}
			@Override
			public void run() {
				jsonResponse = signPlaintextInternal(plaintext, alias);
			}
		}
		SignPlaintextInternalRunnable spir = new SignPlaintextInternalRunnable();
		
		try {
			SwingUtilities.invokeAndWait(spir);
			
			return spir.getJsonResponse();
		} catch (Exception e) {
			logger.error("Internal sign plaintext failed", e);
			
			return "";
		}
	}
	
	/**
	 * Check whether any eligible certificates are available 
	 * @return true if eligible certificates are available; false otherwise
	 * @category JavaScript exposed method
	 */
	public boolean hasCertificates() {
		KeyStoreProxy proxy = getKeyStoreProxy();
				
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = null;
		
		try {
			aliasX509CertificateChainPair =
				createAliasX509CertificateChainPair(proxy);
		} catch (Exception e) {
			handleError("DSA0002", e);
		}
		
		return !aliasX509CertificateChainPair.isEmpty();
	}
	
	/**
	 * Retrieve a JSON expression of certificate aliases and their corresponding
	 * descriptions
	 * @return a JSON expression
	 * @category JavaScript exposed method
	 */
	public String getAliasedDescriptions() {
		String json = "";
		KeyStoreProxy proxy = getKeyStoreProxy();
				
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = null;
		
		try {
			aliasX509CertificateChainPair =
				createAliasX509CertificateChainPair(proxy);
		} catch (Exception e) {
			handleError("DSA0002", e);
		}

		CertificateTableModel ctm = new CertificateTableModel(
				aliasX509CertificateChainPair, 
				messages);
		Environment.getSingleton().init(ctm);
		
		for (int i=0; i<ctm.getRowCount(); i++) {
			X509Certificate certificate = ctm.getX509Certificate(i);
			if (new Date().compareTo(certificate.getNotAfter()) > 0) {
				continue;
			}
			
			String alias = ctm.getAlias(i);
			
			// Column #0 is the name
			// Column #1 is the friendly name
			String name = (String) ctm.getValueAt(i, 0);
			if (name != null) {
				name = StringEscapeUtils.escapeJavaScript(name);
			}
			String friendlyName = (String) ctm.getValueAt(i, 1);
			if (friendlyName != null) {
				friendlyName = StringEscapeUtils.escapeJavaScript(friendlyName);
			}
			String compositeName = (friendlyName != null && friendlyName.length() > 0) ?
					(friendlyName + " - " + name) :
					name;
					
			String entry = "{ \"alias\": \"" + alias + "\", \"description\": \"" + compositeName + "\" }";
			
			if (json.length() > 0) { json += ", "; }
			json += entry;
		}
		
		return "[ " + json + " ]";
	}
	
	private String getSelectedAlias(
			KeyStoreProxy proxy,
			Map<String, X509Certificate[]> aliasX509CertificateChainPair, 
			Profiler profiler) {
		profiler.start("Keypair filtering");
		
		try {
			aliasX509CertificateChainPair = createAliasX509CertificateChainPair(proxy);
		} catch (Exception e) {
			handleError("DSA0002", e);
		}
		
		if (aliasX509CertificateChainPair.isEmpty()) {
			if (noCertificatesJSFunction != null) {
				LiveConnectProxy.getSingleton().eval(noCertificatesJSFunction + "();");
				
				return null;
			} else {
				logger.debug("noCertificatesJSFunction not set");
			}
		}
		
		profiler.start("User selection");
		
		CertificateTableModel ctm = new CertificateTableModel(
					aliasX509CertificateChainPair,
					messages);
		Environment.getSingleton().init(ctm);
		
		SelectCertificateDialog scd = new SelectCertificateDialog(
				ctm,
				expirationDateChecked,
				messages);
		
		scd.setModalityType(ModalityType.APPLICATION_MODAL);
		scd.setVisible(true);

		return scd.getSelectedAlias();
	}
	
	private boolean signInternal(String formId, String alias) {
		Profiler profiler = new Profiler("SIGNATURE");
		profiler.setLogger(logger);
		
		try { // Only for the purpose of stopping the Profiler on final 
			
		if (!started) {
			return false;
		}
		
		profiler.start("Keystore creation");
		
		KeyStoreProxy proxy = getKeyStoreProxy();
		
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = 
				new HashMap<String, X509Certificate[]>();

		if (alias == null) {
			alias = getSelectedAlias(
					proxy, 
					aliasX509CertificateChainPair, 
					profiler);
		}
		
		if (alias == null) {
			return false;
		}
		
		logger.debug("Selected alias: [{}]", alias);
		
		PrivateKey privateKey = null;
		try {
			privateKey = proxy.getPrivateKey(alias);
		} catch (Exception e) {
			handleError("DSA0003", e);
		}

		X509Certificate[] certificateChain = null;
		try {
			certificateChain = proxy.getX509CertificateChain(alias);
		} catch (Exception e) {
			handleError("DSA0004", e);
		}
		
		profiler.start("HTML form parsing");
		
		Strategy strategy = strategyFactory.getStrategy();
		
		FormParser parser = new FormParser(this, formId);
		parser.setContentHandler(
				strategy.getFormContentHandler());
		try {
			DOMService.getService(this).invokeAndWait(parser.getParsingDOMAction());
		} catch (Exception e) {
			handleError("DSA0005", e);
		}
		
		profiler.start("Signature strategy");
		
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
		
		} finally {
			profiler.stop().log();
		}
	}
	
	public String signPlaintextInternal(final String plaintext, String alias) {
		Profiler profiler = new Profiler("PLAINTEXT SIGNATURE");
		profiler.setLogger(logger);
		
		try { // Only for the purpose of stopping the Profiler on final 
			
		if (!started) {
			return null;
		}
		
		profiler.start("Keystore creation");
		
		KeyStoreProxy proxy = getKeyStoreProxy();
		
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = 
				new HashMap<String, X509Certificate[]>();

		if (alias == null) {
			alias = getSelectedAlias(
					proxy, 
					aliasX509CertificateChainPair, 
					profiler);
		}
		
		if (alias == null) {
			return null;
		}
		
		logger.debug("Selected alias: [{}]", alias);
		
		PrivateKey privateKey = null;
		try {
			privateKey = proxy.getPrivateKey(alias);
		} catch (Exception e) {
			handleError("DSA0003", e);
		}

		X509Certificate[] certificateChain = null;
		try {
			certificateChain = proxy.getX509CertificateChain(alias);
		} catch (Exception e) {
			handleError("DSA0004", e);
		}
		
		Strategy strategy = strategyFactory.getStrategy();
		
		profiler.start("Signature strategy");
		
		String jsonResponse = null;
		try {
			jsonResponse = strategy.signPlaintext(plaintext, privateKey, certificateChain);
		} catch (Exception e) {
			handleError("DSA0006", e);
		}
		
		if (successJSFunction != null) {
			LiveConnectProxy.getSingleton().eval(successJSFunction + "();");
		} else {
			logger.debug("successJSFunction not set");
		}
		
		return jsonResponse;
		
		} finally {
			profiler.stop().log();
		}
	}

	private Map<String, X509Certificate[]> createAliasX509CertificateChainPair(KeyStoreProxy ksh)
	throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		Map<String, X509Certificate[]> aliasX509CertificateChainPair = 
			new HashMap<String, X509Certificate[]>();
			
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
					"; certificate.alias=" + alias +
					", certificate.subject=" + subjectName +
					", certificate.serialNumber=" + serialNumber);
			
			aliasX509CertificateChainPair.put(alias, ksh.getX509CertificateChain(alias));
		}
		
		return aliasX509CertificateChainPair;
	}
	
	@Override
	public String getAppletInfo() {
		return "Digital Signature Applet - " +
			DSAPPLET_VERSION +
			"\nCopyright \u00a9 2007-2010 Anestis Georgiadis" +
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
		}
		
		if (cause instanceof RuntimeException) {
			throw (RuntimeException) cause;
		} else {
			throw new RuntimeException(cause);
		}
	}
	

}
