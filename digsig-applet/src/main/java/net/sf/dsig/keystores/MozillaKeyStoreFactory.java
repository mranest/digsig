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

package net.sf.dsig.keystores;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.KeyStore.ProtectionParameter;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import net.sf.dsig.LiveConnectProxy;
import net.sf.dsig.helpers.IniContentHandler;
import net.sf.dsig.helpers.IniParser;
import net.sf.dsig.helpers.UserAgentParser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.pkcs11.SunPKCS11;

public class MozillaKeyStoreFactory implements KeyStoreFactory {
    
    private static final Logger logger = 
            LoggerFactory.getLogger(MozillaKeyStoreFactory.class);

    /**
     * @see net.sf.dsig.keystores.KeyStoreFactory#getKeyStore()
     */
    @Override
    public KeyStore getKeyStore() throws Exception {
        UserAgentParser uap = new UserAgentParser(
                LiveConnectProxy.getSingleton().getUserAgent());
        
        if (!uap.getNames().contains("Gecko")) {
            return null;
        }

        // Take care to initialize the provider only once !!!
        boolean providerRegistered = false;
        for (Provider p : Security.getProviders()) {
            if (p.getName().equals("SunPKCS11-NSSCrypto")) {
                providerRegistered = true;
                break;
            }
        }

        if (!providerRegistered) {
            Provider p = null;
            try {
                p = new SunPKCS11(new ByteArrayInputStream(
                        getMozillaConfiguration(true).getBytes()));
            } catch (ProviderException e) {
                if (    e.getCause() != null &&
                        e.getCause().getClass().getName().equals("sun.security.pkcs11.ConfigurationException")) {
                    logger.debug("Error while instantiating SunPKCS11 provider; retrying without nssLibraryDirectory", e);
                    p = new SunPKCS11(new ByteArrayInputStream(
                            getMozillaConfiguration(false).getBytes()));
                } else {
                    throw e;
                }
            }
            Security.addProvider(p);
        }
        
        KeyStore ks = KeyStore.getInstance("PKCS11-NSSCrypto");
        ks.load(new KeyStore.LoadStoreParameter() {
            public ProtectionParameter getProtectionParameter() {
                return new KeyStore.CallbackHandlerProtection(
                        new PasswordEntryCallbackHandler("NSSCrypto"));
            }
        });

        return ks;
    }

    /**
     * @return
     */
    private String getMozillaConfiguration(boolean nssLibraryDirectoryIncluded) 
    throws Exception {
        File firefoxProfilesPath = null;
        if (System.getProperty("os.name").startsWith("Windows")) {
            String envDataPath = System.getenv("APPDATA");
            firefoxProfilesPath = new File(envDataPath, "Mozilla/Firefox");
        } else if (System.getProperty("os.name").startsWith("Linux")) {
            String userHomePath = System.getProperty("user.home");
            firefoxProfilesPath = new File(userHomePath, ".mozilla/firefox");
        } else if (System.getProperty("os.name").startsWith("Mac OS X")) {
            String userHomePath = System.getProperty("user.home");
            firefoxProfilesPath = new File(userHomePath, "Library/Application Support/Firefox");
        } else {
            throw new UnsupportedOperationException("Usupported OS: os.name=" +
                    System.getProperty("os.name"));
        }

        IniParser p = new IniParser();

        FileInputStream fis = new FileInputStream(
                new File(firefoxProfilesPath, "profiles.ini"));
        ProfileIniContentHandler pich = new ProfileIniContentHandler();
        p.setContentHandler(pich);
        p.parse(fis);
        String defaultProfilePath = pich.getDefaultProfilePath();

        File nssSecmodPath = null;
        if (pich.isRelative()) {
            nssSecmodPath = new File(firefoxProfilesPath, defaultProfilePath);
        } else {
            nssSecmodPath = new File(defaultProfilePath);
        }
        
        String nssSecmodDirectory = "\"" + nssSecmodPath.getAbsolutePath().replace("\\", "/") +  "\"";

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        ps.println("name = NSSCrypto");
        ps.println("nssSecmodDirectory = " + nssSecmodDirectory);
        
        if (nssLibraryDirectoryIncluded) {
            fis = new FileInputStream(
                    new File(nssSecmodPath, "compatibility.ini"));
            CompatibilityIniContentHandler cich = new CompatibilityIniContentHandler();
            p.setContentHandler(cich);
            p.parse(fis);
            String lastAppDir = cich.getLastAppDir();
            File nssLibraryPath = null;
            if (lastAppDir != null) {
                nssLibraryPath = new File(lastAppDir);
            }
            
            if (nssLibraryPath == null || !nssLibraryPath.exists()) {
                String lastPlatformDir = cich.getLastPlatformDir();
                if (lastPlatformDir != null) {
                    nssLibraryPath = new File(lastPlatformDir);
                }
            }
    
            if (nssLibraryPath != null && nssLibraryPath.exists()) {
                String nssLibraryDirectory = nssLibraryPath.getAbsolutePath().replace("\\", "/");
                
                // nssLibraryDirectory setting might cause the following error:
                // java.security.ProviderException: Error parsing configuration
                //
                // This occurs in Windows x64 OSes, because of the use of 
                // parentheses in 'Program Files (x86)' part of the path.
                ps.println("nssLibraryDirectory = " + nssLibraryDirectory);
            }
        }
        ps.close();

        String configuration = new String(baos.toByteArray()); 
        logger.debug("SunPKCS11 configuration:\n" + configuration);
        return configuration;
    }
    
    public class CompatibilityIniContentHandler implements IniContentHandler {

        private String lastAppDir;
        
        public String getLastAppDir() {
            return lastAppDir;
        }
        
        private String lastPlatformDir;
        
        public String getLastPlatformDir() {
            return lastPlatformDir;
        }
        
        /**
         * @see net.sf.dsig.helpers.IniContentHandler#onEntry(java.lang.String, java.lang.String)
         */
        @Override
        public void onEntry(String name, String value) {
            if (name.equals("LastAppDir")) {
                lastAppDir = value;
            }
            if (name.equals("LastPlatformDir")) {
                lastPlatformDir = value;
            }
        }

        public void onEnd() { /* NO-OP */ }

        public void onSection(String sectionName) { /* NO-OP */ }

        public void onStart() { /* NO-OP */ }

    }
    
    /**
     * Our pre-defined ContentHandler implementation for retrieving
     * the path of the default Firefox profile.
     *
     * @author AGeorgiadis
     */
    public class ProfileIniContentHandler implements IniContentHandler {

        private boolean defaultProfile = false;
        private boolean relative = false;
        private String defaultProfilePath = null;

        public boolean isRelative() {
            return relative;
        }

        public String getDefaultProfilePath() {
            return defaultProfilePath;
        }

        public void onEntry(String name, String value) {
            if ("Name".equals(name)) {
                defaultProfile = "default".equals(value);
            } else if ("IsRelative".equals(name)) {
                relative = "1".equals(value);
            } else if ("Path".equals(name) && defaultProfile) {
                defaultProfilePath = value;
            }
        }

        public void onEnd() { /* NO-OP */ }

        public void onSection(String sectionName) { /* NO-OP */ }

        public void onStart() { /* NO-OP */ }

    }

    public static class PasswordEntryCallbackHandler implements CallbackHandler {
        
        private final String name;
        
        public PasswordEntryCallbackHandler(String name) {
            this.name = name;
        }

        public void handle(Callback[] callbacks) throws IOException,
                UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback) callback;
                    
                    JPasswordField passwordField = new JPasswordField();
                    passwordField.setEchoChar('*');
                    JOptionPane.showMessageDialog(
                            null, 
                            passwordField,
                            "Enter master password (" + name + "):",
                            JOptionPane.QUESTION_MESSAGE);
                    // String password = JOptionPane.showInputDialog("Please enter the master password (" + name + "):");
                    // passwordCallback.setPassword(password.toCharArray());
                    
                    passwordCallback.setPassword(passwordField.getPassword());
                }
            }
        }

    }

}
