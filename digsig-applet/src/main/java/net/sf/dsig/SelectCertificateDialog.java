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

package net.sf.dsig;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.ResourceBundle;
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
import javax.swing.table.DefaultTableCellRenderer;

/**
 * The dialog box for selecting certificates (actually, key/certificate pairs)
 */
public class SelectCertificateDialog extends JDialog 
implements ActionListener, KeyListener, MouseListener, ListSelectionListener {
    
    private static final String TITLE = "selectCertificateDialog.title";
    private static final String DETAILS = "selectCertificateDialog.details";
    private static final String DEFAULT_TEXT = "selectCertificateDialog.defaultText";
    private static final String CANCEL = "selectCertificateDialog.cancel";
    private static final String EXPIRED = "selectCertificateDialog.expired";

    private final boolean expirationDateChecked;
    private final ResourceBundle messages;

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
    
    public SelectCertificateDialog(
            CertificateTableModel ctm, 
            ResourceBundle messages) {
        this(ctm, true, messages);
    }
    
    public SelectCertificateDialog(
            CertificateTableModel ctm, 
            boolean expirationDateChecked,
            ResourceBundle messages) {
        this.certificateTableModel = ctm;

        this.expirationDateChecked = expirationDateChecked;
        this.messages = messages;
        
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

        // Can render either two or three columns; always pick the last
        certificateTable.getColumnModel().getColumn(certificateTable.getColumnCount()-1)
                .setCellRenderer(new DateRenderer());
        
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
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
                messages.getString(DETAILS)));
        detailsTextArea = new JTextArea(
                messages.getString(DEFAULT_TEXT));
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
        
        cancelButton = new JButton(messages.getString(CANCEL));
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
        
        // This is the event thrown when clicking the window close button
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                certificateTable.clearSelection();
                super.windowClosing(e);
            }
        });
        
        getRootPane().setDefaultButton(okButton);
        
        setTitle(this.messages.getString(TITLE));
        setResizable(false);
        
        // Preselect the first row, if only one valid certificate
        // is printed
        if (    certificateTableModel.getCertificateCount() == 1 &&
                certificateTableModel.getValidCertificateCount() == 1) {
            certificateTable.setRowSelectionInterval(0, 0);
            certificateTable.setColumnSelectionInterval(0, certificateTableModel.getColumnCount()-1);
            
            updateDetailsTextArea(getSelectedX509Certificate());
        }
        
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
    
    public void valueChanged(ListSelectionEvent e) {
        if (    getSelectedRow() != -1 &&
                (!expirationDateChecked || !isExpired(getSelectedX509Certificate().getNotAfter()))) {
            okButton.setEnabled(true);
        } else {
            okButton.setEnabled(false);
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
            if (okButton.isEnabled()) {
                setVisible(false);
            }
            break;
        }       
    }

    public void keyReleased(KeyEvent e) {
        switch (e.getKeyCode()) {
        case KeyEvent.VK_UP:
        case KeyEvent.VK_DOWN:
        case KeyEvent.VK_ENTER: // Handled here because an enter event that
                                // normally advances the selected line in the
                                // table
            X509Certificate certificate = getSelectedX509Certificate();
            updateDetailsTextArea(certificate);
            break;
        }
    }

    public void keyTyped(KeyEvent e) {
        // NO-OP
    }
    
    private void updateDetailsTextArea(X509Certificate certificate) {
        if (certificate != null) {
            detailsTextArea.setText(getFilteredDetails(certificate));
            detailsTextArea.setCaretPosition(0);
            
            if (    expirationDateChecked && 
                    isExpired(certificate.getNotAfter())) {
                
            }
        } else {
            detailsTextArea.setText(
                    messages.getString(DEFAULT_TEXT));
        }
    }

    public void mouseClicked(MouseEvent e) {
        if (e.getSource() == certificateTable) {
            X509Certificate certificate = getSelectedX509Certificate();
            if (e.getClickCount() == 2 && okButton.isEnabled()) {
                setVisible(false);
            } else {
                updateDetailsTextArea(certificate);
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
        
        if (    expirationDateChecked && 
                isExpired(certificate.getNotAfter())) {
            sb.append(
                    messages.getString(EXPIRED));
            sb.append("\n");
        }
        
        String[] fields = certificate.getSubjectX500Principal()
                .getName(X500Principal.RFC2253, oidMap).split(",");
        
        boolean valueAdded = false;
        for (String field : fields) {
            String[] parts = field.split("=");
            String name = (parts.length == 2)?parts[0].trim():"";
            if (!allowedValues.contains(name.toUpperCase())) {
                continue;
            }
            Component c = Component.valueOf(name.toUpperCase());
            
            if (!valueAdded) {
                valueAdded = true;
            } else {
                sb.append("\n");
            }
            
            sb.append(c.getName());
            sb.append(": ");
            sb.append(parts[1]);
        }
        
        return sb.toString();
    }

    private class DateRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 8322588573328968592L;
        DateFormat formatter = null;

        @Override
        protected void setValue(Object value) {
            if (formatter == null) {
                formatter = DateFormat.getDateInstance();
            }

            if (!(value instanceof Date)) {
                super.setValue(value);
            } else {
                setText(value == null ? "" : formatter.format(value));
            }
        }

        @Override
        public java.awt.Component getTableCellRendererComponent(JTable table,
                Object value, boolean isSelected, boolean hasFocus, int row,
                int column) {
            java.awt.Component component = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            
            if (expirationDateChecked) {
                boolean expired = isExpired((Date) value);
                if (isSelected) {
                    component.setForeground(expired ? Color.WHITE : table.getSelectionForeground());
                    component.setBackground(expired ? Color.RED : table.getSelectionBackground());
                } else {
                    component.setForeground(expired ? Color.WHITE : table.getForeground());
                    component.setBackground(expired ? Color.RED : table.getBackground());
                }
            }

            return component;
        }
    }

    private boolean isExpired(Date notAfter) {
        return new Date().compareTo(notAfter) > 0;
    }
    
}
