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

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;
import javax.swing.table.AbstractTableModel;

public class CertificateTableModel extends AbstractTableModel {
	
	private static final long serialVersionUID = 1821906345886093491L;
	
	private final LinkedHashMap<String, X509Certificate[]> aliasX509CertificateChainMap;
	
	public CertificateTableModel(Map<String, X509Certificate[]> aliasX509CertificateChainMap) {
		this.aliasX509CertificateChainMap = 
			new LinkedHashMap<String, X509Certificate[]>(aliasX509CertificateChainMap);
	}

	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	public int getColumnCount() {
		return 3;
	}

	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
		case 0:
			return "Issued To";
		case 1:
			return "Issued By";
		case 2:
			return "Expiration Date";
		default:
			return null;
		}
	}

	public int getRowCount() {
		return aliasX509CertificateChainMap.size();
	}
	
	private Pattern cnPattern = Pattern.compile(".*CN=([^,]*).*");
	
	private String getX500CN(String name) {
		Matcher m = cnPattern.matcher(name);
		if (m.matches()) {
			return m.group(1);
		} else {
			return name;
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
		X500Principal issuerPrincipal = certificate.getIssuerX500Principal();
		
		switch (columnIndex) {
		case 0:
			return getX500CN(subjectPrincipal.getName());
		case 1:
			return getX500CN(issuerPrincipal.getName());
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
