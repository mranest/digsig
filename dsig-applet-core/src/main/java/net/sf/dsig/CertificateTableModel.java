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

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;
import javax.swing.table.AbstractTableModel;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CertificateTableModel extends AbstractTableModel {
	
	private static final long serialVersionUID = 1821906345886093491L;

	private static final Log logger = LogFactory.getLog(CertificateTableModel.class);
	
	private static final String ISSUED_TO = "certificateTableModel.issuedTo";
	private static final String FRIENDLY_NAME = "certificateTableModel.friendlyName";
	private static final String EXPIRATION_DATE = "certificateTableModel.expirationDate";
	
	private static final String SUBJECT_NAME_REGEX_DEFAULT = ".*CN=([^,]*).*";
	
	private String subjectNameRegex = SUBJECT_NAME_REGEX_DEFAULT;
	
	public void setSubjectNameRegex(String subjectNameRegex) {
		if (subjectNameRegex != null) {
			this.subjectNameRegex = subjectNameRegex;
		}
	}
	
	private Pattern subjectNamePattern;
	
	private Pattern getSubjectNamePattern() {
		if (subjectNamePattern == null) {
			subjectNamePattern = Pattern.compile(subjectNameRegex); 
		}
		
		return subjectNamePattern;
	}
	
	private static final String SUBJECT_FRIENDLY_REGEX_DEFAULT = ".*OU=Alias - ([^,]*).*";

	private String subjectFriendlyRegex = SUBJECT_FRIENDLY_REGEX_DEFAULT;
	
	public void setSubjectFriendlyRegex(String subjectFriendlyRegex) {
		// Can be set to null, or empty string
		if (	subjectFriendlyRegex == null ||
				subjectFriendlyRegex.length() == 0) {
			logger.debug("Disabling display of friendly name");
			this.subjectFriendlyRegex = null;
		} else {
			this.subjectFriendlyRegex = subjectFriendlyRegex;
		}
	}
	
	private Pattern subjectFriendlyPattern;
	
	private Pattern getSubjectFriendlyPattern() {
		if (subjectFriendlyRegex == null) {
			return null;
		}
		
		if (subjectFriendlyPattern == null) {
			subjectFriendlyPattern = Pattern.compile(subjectFriendlyRegex);
		}
		
		return subjectFriendlyPattern;
	}
	
	private final LinkedHashMap<String, X509Certificate[]> aliasX509CertificateChainMap;
	
	private final ResourceBundle messages;
	
	public CertificateTableModel(
			Map<String, X509Certificate[]> aliasX509CertificateChainMap,
			ResourceBundle messages) {
		this.aliasX509CertificateChainMap = 
			new LinkedHashMap<String, X509Certificate[]>(aliasX509CertificateChainMap);
		this.messages = messages;
	}

	public CertificateTableModel(
			Map<String, X509Certificate[]> aliasX509CertificateChainMap,
			String subjectNameRegex,
			String subjectFriendlyRegex,
			ResourceBundle messages) {
		this(aliasX509CertificateChainMap, messages);
		setSubjectNameRegex(subjectNameRegex);
		setSubjectFriendlyRegex(subjectFriendlyRegex);
	}
	
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	public int getColumnCount() {
		return getSubjectFriendlyPattern() != null ? 3 : 2;
	}

	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
		case 0:
			return messages.getString(ISSUED_TO);
		case 1:
			return getSubjectFriendlyPattern() != null ?
					messages.getString(FRIENDLY_NAME) :
					messages.getString(EXPIRATION_DATE);
		case 2:
			return messages.getString(EXPIRATION_DATE);
		default:
			return null;
		}
	}

	public int getRowCount() {
		return aliasX509CertificateChainMap.size();
	}
	
	private String getSubjectComponent(String s, Pattern p) {
		Matcher m = p.matcher(s);
		if (m.matches()) {
			return m.group(1);
		} else {
			return "";
		}
	}
	
	public Object getValueAt(int rowIndex, int columnIndex) {
		Iterator<String> aliasIterator = aliasX509CertificateChainMap.keySet().iterator();
		String alias = null;
		for (int i=0; i<=rowIndex; i++) {
			alias = aliasIterator.next();
		}
		
		X509Certificate certificate = aliasX509CertificateChainMap.get(alias)[0];
		
		X500Principal subjectPrincipal = certificate.getSubjectX500Principal();
		
		switch (columnIndex) {
		case 0:
			return getSubjectComponent(subjectPrincipal.getName(), getSubjectNamePattern());
		case 1:
			return getSubjectFriendlyPattern() != null ?
					getSubjectComponent(subjectPrincipal.getName(), getSubjectFriendlyPattern()) :
					certificate.getNotAfter();
		case 2:
			return certificate.getNotAfter();
		default:
			return null;
		}
	}

	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		throw new UnsupportedOperationException("setValueAt() not supported");
	}

	public String getAlias(int rowNum) {
		if (rowNum < 0 || rowNum > aliasX509CertificateChainMap.size()) {
			return null;
		}
		
		Iterator<String> aliasIterator = aliasX509CertificateChainMap.keySet().iterator();
		String alias = null;
		for (int i=0; i<=rowNum; i++) {
			alias = aliasIterator.next();
		}
		
		return alias;
	}
	
	public X509Certificate getX509Certificate(int rowNum) {
		String alias = getAlias(rowNum);
		
		if (alias == null) {
			return null;
		} else {
			return aliasX509CertificateChainMap.get(alias)[0];
		}
	}
	
}
