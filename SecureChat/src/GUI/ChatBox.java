/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package GUI;

import securechat.SecureNode;
import GUIInterface.Writable;
import Networking.Server;
import Networking.Client;
import java.awt.Font;

/**
 *
 * @author sathya
 */
public class ChatBox extends javax.swing.JFrame implements Writable{
    SecureNode curr = null;
    /**
     * Creates new form ChatBox
     */
    public ChatBox() {
        initComponents();
    }
    public ChatBox(SecureNode d){
        this.curr =d;
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        ApplicationName = new javax.swing.JLabel();
        ListenButton = new javax.swing.JButton();
        PortIn = new javax.swing.JTextField();
        PrtLabel = new javax.swing.JLabel();
        IpaddrIn = new javax.swing.JTextField();
        Iplabel = new javax.swing.JLabel();
        SendButton = new javax.swing.JButton();
        MessageIn = new javax.swing.JTextField();
        Myport = new javax.swing.JTextField();
        ListenPort = new javax.swing.JLabel();
        AKEinit = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        ChatDisplay = new javax.swing.JTextArea();
        AKElast = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setForeground(java.awt.Color.black);

        ApplicationName.setText("ChatSecure");

        ListenButton.setText("Listen");
        ListenButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ListenButtonActionPerformed(evt);
            }
        });

        PortIn.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        PortIn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PortInActionPerformed(evt);
            }
        });

        PrtLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        PrtLabel.setText("Port");
        PrtLabel.setToolTipText("");

        IpaddrIn.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        IpaddrIn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IpaddrInActionPerformed(evt);
            }
        });

        Iplabel.setText("IP");

        SendButton.setText("Send");
        SendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SendButtonActionPerformed(evt);
            }
        });

        MessageIn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MessageInActionPerformed(evt);
            }
        });

        Myport.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N

        ListenPort.setText("Myport");

        AKEinit.setText("AKE1");
        AKEinit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AKEinitActionPerformed(evt);
            }
        });

        ChatDisplay.setColumns(20);
        ChatDisplay.setRows(5);
        jScrollPane1.setViewportView(ChatDisplay);

        AKElast.setText("AKE2");
        AKElast.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AKElastActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(69, 69, 69)
                .addComponent(MessageIn, javax.swing.GroupLayout.PREFERRED_SIZE, 1528, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(65, 65, 65)
                .addComponent(SendButton, javax.swing.GroupLayout.PREFERRED_SIZE, 112, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(317, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(ApplicationName, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(35, 35, 35)
                        .addComponent(ListenPort, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(Myport, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(31, 31, 31)
                        .addComponent(Iplabel, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(IpaddrIn, javax.swing.GroupLayout.PREFERRED_SIZE, 434, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(PrtLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(PortIn, javax.swing.GroupLayout.PREFERRED_SIZE, 123, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(136, 136, 136)
                        .addComponent(AKEinit)
                        .addGap(70, 70, 70)
                        .addComponent(AKElast)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(ListenButton, javax.swing.GroupLayout.PREFERRED_SIZE, 124, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(286, 286, 286))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(Iplabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(29, 29, 29))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(AKElast, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ApplicationName, javax.swing.GroupLayout.DEFAULT_SIZE, 71, Short.MAX_VALUE)
                            .addComponent(IpaddrIn, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(PortIn, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(PrtLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Myport)
                            .addComponent(ListenPort, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(AKEinit, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ListenButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)))
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 844, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(SendButton, javax.swing.GroupLayout.DEFAULT_SIZE, 89, Short.MAX_VALUE)
                    .addComponent(MessageIn))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    Client listen;
    Server init ;
    SecureNode d;
    private void ListenButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ListenButtonActionPerformed
        // TODO add your handling code here:
        listen = new Client(Integer.parseInt(Myport.getText()),this,init,this.curr);
        listen.start();
        System.out.println("listening ");
    }//GEN-LAST:event_ListenButtonActionPerformed
 
    private void IpaddrInActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IpaddrInActionPerformed
        // TODO add your handling code here:
         
    }//GEN-LAST:event_IpaddrInActionPerformed

    private void PortInActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PortInActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_PortInActionPerformed
    
    private void SendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SendButtonActionPerformed
        // TODO add your handling code here:
        init = new Server(Integer.parseInt(PortIn.getText()),IpaddrIn.getText(),MessageIn.getText(),this.curr);
         init.initialise();
    }//GEN-LAST:event_SendButtonActionPerformed
         Server authServer;
    private void AKEinitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AKEinitActionPerformed
        // TODO add your handling code here:
        authServer= new Server(Integer.parseInt(PortIn.getText()),IpaddrIn.getText(),this.curr);
        authServer.initialise();
    }//GEN-LAST:event_AKEinitActionPerformed

    private void AKElastActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AKElastActionPerformed
         // TODO add your handling code here:
         authServer.initialise();
    }//GEN-LAST:event_AKElastActionPerformed

    private void MessageInActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MessageInActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_MessageInActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ChatBox().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton AKEinit;
    private javax.swing.JButton AKElast;
    private javax.swing.JLabel ApplicationName;
    private javax.swing.JTextArea ChatDisplay;
    private javax.swing.JTextField IpaddrIn;
    private javax.swing.JLabel Iplabel;
    private javax.swing.JButton ListenButton;
    private javax.swing.JLabel ListenPort;
    private javax.swing.JTextField MessageIn;
    private javax.swing.JTextField Myport;
    private javax.swing.JTextField PortIn;
    private javax.swing.JLabel PrtLabel;
    private javax.swing.JButton SendButton;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables

    
    @Override
    public void write(String s) {
        Font font_dis = new Font("SansSerif", Font.BOLD, 20);
        ChatDisplay.setFont(font_dis);
        
        ChatDisplay.append(s+System.lineSeparator());
    }
}
