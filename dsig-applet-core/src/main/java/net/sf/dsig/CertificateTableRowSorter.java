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

import java.util.Comparator;
import java.util.Date;

import javax.swing.table.TableRowSorter;

public class CertificateTableRowSorter extends TableRowSorter<CertificateTableModel> {

	public CertificateTableRowSorter(CertificateTableModel ctm) {
		super(ctm);
	}
	
	@Override
	public Comparator<?> getComparator(int column) {
		if (column != 2) {
			return super.getComparator(column);
		} else {
			return new Comparator<Date>() {
				public int compare(Date o1, Date o2) {
					return o1.compareTo(o2);
				}
			};
		}
	}
	
}
