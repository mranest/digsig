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
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.ProtectionParameter;

import net.sf.dsig.keystores.MozillaKeyStoreFactory.PasswordEntryCallbackHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.pkcs11.SunPKCS11;

public class Pkcs11KeyStoreFactory implements KeyStoreFactory {

    private static final Logger LOGGER = 
            LoggerFactory.getLogger(Pkcs11KeyStoreFactory.class);
    
    private final String name;
    
    private final String library;
    
    public Pkcs11KeyStoreFactory(String name, String library) {
        this.name = name;
        this.library = library;
    }
    
    /**
     * @see net.sf.dsig.keystores.KeyStoreFactory#getKeyStore()
     */
    @Override
    public KeyStore getKeyStore() throws Exception {
        Provider p = new SunPKCS11(new ByteArrayInputStream(
                    getPkcs11Configuration(name, library).getBytes()));
        Security.addProvider(p);
        
        KeyStore ks = KeyStore.getInstance("PKCS11-" + name);

        ks.load(new KeyStore.LoadStoreParameter() {
            public ProtectionParameter getProtectionParameter() {
                return new KeyStore.CallbackHandlerProtection(
                        new PasswordEntryCallbackHandler(name));
            }
        });
        
        return ks;
    }

    private String getPkcs11Configuration(String pkcs11Name, String pkcs11Library) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        ps.println("name = " + pkcs11Name);
        ps.println("library = " + pkcs11Library);
        
        ps.close();

        String configuration = new String(baos.toByteArray()); 
        LOGGER.debug("SunPKCS11 configuration:\n" + configuration);
        
        return configuration;
    }

}
