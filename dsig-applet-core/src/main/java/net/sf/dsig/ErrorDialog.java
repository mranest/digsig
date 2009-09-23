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

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;

/**
 * ErrorDialog class defines the behavior for the dialog box that pops
 * up when an error occurs.
 */
public class ErrorDialog extends JDialog 
implements ActionListener, KeyListener {
	
	private static final long serialVersionUID = -1074978716305785744L;

	private final JLabel errorLabel;
	private final JTextArea causeTextArea;
	private final JButton okButton;
	
	public ErrorDialog(String errorCode, Throwable cause, ResourceBundle bundle) {
		JPanel contentPane = new JPanel();
		contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.PAGE_AXIS));
		contentPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		
		errorLabel = new JLabel(errorCode + ": " + bundle.getString(errorCode));
		errorLabel.setAlignmentX(JComponent.LEFT_ALIGNMENT);
		contentPane.add(errorLabel);
		
		contentPane.add(new JSeparator());
		contentPane.add(Box.createVerticalStrut(5));
		
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		cause.printStackTrace(pw);
		pw.close();
		
		causeTextArea = new JTextArea(sw.toString());
		causeTextArea.setOpaque(true);
		causeTextArea.setFont(errorLabel.getFont());
//		causeTextArea.setRows(10);
		causeTextArea.setEditable(false);
		
		JScrollPane causeScrollPane = new JScrollPane(causeTextArea);
		causeScrollPane.setBorder(BorderFactory.createEmptyBorder());
		causeScrollPane.setMinimumSize(new Dimension(500, 150));
		causeScrollPane.setPreferredSize(new Dimension(500, 150));
		causeScrollPane.setAlignmentX(JComponent.LEFT_ALIGNMENT);
		contentPane.add(causeScrollPane);
		
		contentPane.add(Box.createVerticalStrut(5));
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.LINE_AXIS));
		
		okButton = new JButton("OK");
		okButton.addActionListener(this);
		okButton.addKeyListener(this);
		okButton.setFocusable(true);
		okButton.setPreferredSize(new Dimension(73, 23));
		
		buttonPanel.add(Box.createHorizontalGlue());
		buttonPanel.add(okButton);
		buttonPanel.add(Box.createHorizontalGlue());
		buttonPanel.setAlignmentX(JComponent.LEFT_ALIGNMENT);
		contentPane.add(buttonPanel);
		
		setContentPane(contentPane);
		
		getRootPane().setDefaultButton(okButton);
		
		setTitle("Error Details");
		setResizable(false);
		pack();
	}

	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == okButton) {
			setVisible(false);
		}
	}

	public void keyPressed(KeyEvent e) {
        switch (e.getKeyCode()) {
    	case KeyEvent.VK_ESCAPE:
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
}
