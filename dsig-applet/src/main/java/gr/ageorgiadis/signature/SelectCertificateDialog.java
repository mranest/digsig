package gr.ageorgiadis.signature;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * The dialog box for selecting certificates (actually, key/certificate pairs)
 * 
 * @author AGeorgiadis
 */
public class SelectCertificateDialog extends JDialog 
implements ActionListener, KeyListener, MouseListener, ListSelectionListener {

	private static final long serialVersionUID = 4532062113859797702L;

	// TableModel
	private final CertificateTableModel certificateTableModel;
	
	// GUI Elements
	private final JTable certificateTable;
	private final JTextArea detailsTextArea;
	private final JButton okButton;
	private final JButton cancelButton;

	// X.500 OID map
	private final Map<String, String> oidMap;
	
	public SelectCertificateDialog(CertificateTableModel ctm, String providerName) {
		this.certificateTableModel = ctm;
		
		// Fill the OID map with well-known OIDs that need to be displayed
		oidMap = new HashMap<String, String>();
		oidMap.put("1.2.840.113549.1.9.1", "E");
		
		JPanel contentPane = new JPanel();
		contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.PAGE_AXIS));
		contentPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		
		certificateTable = new JTable(certificateTableModel);
		certificateTable.addKeyListener(this);
		certificateTable.addMouseListener(this);
		certificateTable.getSelectionModel().addListSelectionListener(this);
		
		certificateTable.setShowGrid(false);
		certificateTable.setIntercellSpacing(new Dimension(0, 0));
		certificateTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		
		certificateTable.setColumnSelectionAllowed(false);
		certificateTable.setCellSelectionEnabled(false);
		certificateTable.setRowSelectionAllowed(true);
		
		certificateTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		certificateTable.setRowSorter(
				new CertificateTableRowSorter(certificateTableModel));

		// TODO Need to find a way for the dotted line of the selection to
		// wrap the whole row, instead of the cell where the user clicked into
		
		JScrollPane tableScrollPane = new JScrollPane(certificateTable);
		certificateTable.setFillsViewportHeight(true);
		tableScrollPane.setMinimumSize(new Dimension(400, 150));
		tableScrollPane.setPreferredSize(new Dimension(400, 150));
		tableScrollPane.setAlignmentX(java.awt.Component.RIGHT_ALIGNMENT);
	
		contentPane.add(tableScrollPane, BorderLayout.PAGE_START);
		
		JPanel detailsPanel = new JPanel();
		detailsPanel.setLayout(new BoxLayout(detailsPanel, BoxLayout.PAGE_AXIS));
		detailsPanel.setBorder(BorderFactory.createTitledBorder("Key/Certificate Details"));
		detailsTextArea = new JTextArea("No Key/Certificate selected.");
		detailsTextArea.setOpaque(false);
		detailsTextArea.setFont(certificateTable.getFont());
		detailsTextArea.setRows(5);
		detailsTextArea.setEditable(false);
		
		JScrollPane detailsScrollPane = new JScrollPane(detailsTextArea);
		detailsScrollPane.setBorder(BorderFactory.createEmptyBorder());
		detailsScrollPane.setMinimumSize(new Dimension(400, 110));
		detailsScrollPane.setPreferredSize(new Dimension(400, 110));
		detailsScrollPane.setAlignmentX(java.awt.Component.RIGHT_ALIGNMENT);
		
		detailsPanel.add(detailsScrollPane);
		
		contentPane.add(detailsPanel);
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.LINE_AXIS));
		
		okButton = new JButton("OK");
		okButton.addActionListener(this);
		okButton.addKeyListener(this);
		okButton.setFocusable(true);
		okButton.setPreferredSize(new Dimension(73, 23));
		okButton.setEnabled(false);
		
		cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(this);
		cancelButton.addKeyListener(this);
		cancelButton.setFocusable(true);
		cancelButton.setPreferredSize(new Dimension(73, 23));
		
		buttonPanel.add(Box.createHorizontalGlue());
		buttonPanel.add(okButton);
		buttonPanel.add(cancelButton);
		buttonPanel.setAlignmentX(java.awt.Component.RIGHT_ALIGNMENT);
		
		contentPane.add(buttonPanel);
		
		setContentPane(contentPane);
		
		getRootPane().setDefaultButton(okButton);

		setTitle("Key/Certificate Selection (" + providerName + ")");
		setResizable(false);
		pack();
	}

	public int getSelectedRow() {
		if (certificateTable.getSelectedRow() == -1) {
			return -1;
		} else {
			return certificateTable.convertRowIndexToModel(certificateTable.getSelectedRow());
		}
	}
	
	public String getSelectedAlias() {
		if (getSelectedRow() == -1) {
			return null;
		} else {
			return certificateTableModel.getAlias(getSelectedRow());
		}
	}
	
	public X509Certificate getSelectedX509Certificate() {
		if (getSelectedRow() == -1) {
			return null;
		} else {
			return certificateTableModel.getX509Certificate(getSelectedRow());
		}
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == okButton) {
			setVisible(false);
		} else if (e.getSource() == cancelButton) {
			certificateTable.clearSelection();
			setVisible(false);
		}
	}

	public void keyPressed(KeyEvent e) {
        switch (e.getKeyCode()) {
    	case KeyEvent.VK_ESCAPE:
    		certificateTable.clearSelection();
    	    setVisible(false);
    		break;
    	case KeyEvent.VK_TAB:
    	    java.awt.Component comp = getFocusOwner();
    		if (e.isShiftDown()) {
    		    comp.transferFocusBackward();
    		} else {
    		    comp.transferFocus();
    		}
    		break;
    	case KeyEvent.VK_ENTER:
            if (e.getSource() == cancelButton) {
            	certificateTable.clearSelection();
            }
            setVisible(false);
    		break;
        }		
	}

	public void keyReleased(KeyEvent e) {
		// NO-OP
	}

	public void keyTyped(KeyEvent e) {
		// NO-OP
	}

	public void mouseClicked(MouseEvent e) {
		if (e.getSource() == certificateTable) {
			if (e.getClickCount() == 2) {
				setVisible(false);
			} else {
				X509Certificate certificate = getSelectedX509Certificate();
				if (certificate != null) {
					detailsTextArea.setText(getFilteredDetails(certificate));
					detailsTextArea.setCaretPosition(0);
				} else {
					detailsTextArea.setText("No Key/Certificate pair selected.");
				}
			}
		}
	}

	public void mouseEntered(MouseEvent e) {
		// NO-OP
	}

	public void mouseExited(MouseEvent e) {
		// NO-OP
	}

	public void mousePressed(MouseEvent e) {
		// NO-OP
	}

	public void mouseReleased(MouseEvent e) {
		// NO-OP
	}

	private enum Component {
		CN("Canonical Name"),
		E("E-Mail"),
		O("Organization"),
		OU("Organizational Unit"),
		L("Locality"),
		ST("State"),
		C("Country");
		
		private final String name;
		Component(String name) { this.name = name; }
		
		public String getName() { return name; }
	}
	
	private String getFilteredDetails(X509Certificate certificate) {
		Set<String> allowedValues = new HashSet<String>();
		for (Component c : Component.values()) {
			allowedValues.add(c.toString());
		}
		
		StringBuilder sb = new StringBuilder();
		String[] fields = certificate.getSubjectX500Principal()
				.getName(X500Principal.RFC1779, oidMap).split(",");
		
		for (String field : fields) {
			String[] parts = field.split("=");
			String name = (parts.length == 2)?parts[0].trim():"";
			if (!allowedValues.contains(name.toUpperCase())) {
				continue;
			}
			Component c = Component.valueOf(name.toUpperCase());
			
			if (sb.length() > 0) {
				sb.append("\n");
			}
			
			sb.append(c.getName());
			sb.append(": ");
			sb.append(parts[1]);
		}
		
		return sb.toString();
	}

	public void valueChanged(ListSelectionEvent e) {
		if (getSelectedRow() != -1) {
			okButton.setEnabled(true);
		} else {
			okButton.setEnabled(false);
		}
	}
	
}
