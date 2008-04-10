package gr.ageorgiadis.signature;

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
