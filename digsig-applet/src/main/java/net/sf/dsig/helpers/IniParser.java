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

package net.sf.dsig.helpers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class IniParser {

    private IniContentHandler contentHandler = null;
    
    public void setContentHandler(IniContentHandler contentHandler) {
        this.contentHandler = contentHandler;
    }
    
    public void parse(InputStream is) throws MalformedException {
        if (contentHandler != null) {
            // Wrap the InputStream in a BufferedReader
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(is));
            String line = null;
            try {
                while ((line = br.readLine()) != null) {
                    String trimmedLine = line.trim();
                    // Skip empty lines
                    if (trimmedLine == null || trimmedLine.length() == 0) {
                        continue;
                    }
                    // Skip comment lines
                    if (trimmedLine.startsWith("'")) {
                        continue;
                    }
                    
                    if (trimmedLine.startsWith("[")) {
                        // Section
                        if (trimmedLine.indexOf(']') == -1) {
                            throw new MalformedException("Malformed section; missing right bracket");
                        }

                        contentHandler.onSection(trimmedLine.substring(1, 
                                trimmedLine.indexOf("]")));
                    } else {
                        // Entry
                        if (trimmedLine.indexOf('=') == -1) {
                            throw new MalformedException("Malformed entry; missing =");
                        }
                        
                        String name = trimmedLine.substring(0, trimmedLine.indexOf('='));
                        String value = null;
                        if (trimmedLine.indexOf('\'', trimmedLine.indexOf('=')) == -1) {
                            // No comment on the line
                            value = trimmedLine.substring(
                                    trimmedLine.indexOf('=') + 1);
                        } else {
                            // Comment exists; remove it
                            value = trimmedLine.substring(
                                    trimmedLine.indexOf('=') + 1,
                                    trimmedLine.indexOf('\'')).trim();
                        }
                        
                        contentHandler.onEntry(name, value);
                    }
                }
            } catch (IOException e) {
                throw new MalformedException("I/O error during reading", e);
            }

            try {
                br.close();
            } catch (IOException e) {
                throw new MalformedException("I/O error during closing", e);
            }
        }
        
        try {
            is.close();
        } catch (IOException e) {
            throw new MalformedException("I/O error during closing", e);
        }
    }

    public static class MalformedException extends Exception {
        private static final long serialVersionUID = 7902299455923738808L;
        public MalformedException(String message) { super(message); }
        public MalformedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
}
