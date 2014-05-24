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

package net.sf.dsig.verify;

/**
 * A normal exception that represents network access errors
 * 
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class NetworkAccessException extends Exception {

    private static final long serialVersionUID = -4442526270262488256L;

    public NetworkAccessException() { }
    
    public NetworkAccessException(String message) {
        super(message);
    }
    
    public NetworkAccessException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
