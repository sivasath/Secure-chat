/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securechat;
import GUI.ChatBox;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.DHParameterSpec;
/**
 *
 * @author sathya
 */
public class Main {

    
    
    public static void main(String[] args) {
                
            
        try {
             //DH
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            gen.init(1024);
            AlgorithmParameters para = gen.generateParameters();
            DHParameterSpec spec = para.getParameterSpec(DHParameterSpec.class);
            BigInteger g = spec.getG();
            BigInteger p = spec.getP();
            System.out.println("p: "+p);
            int l = spec.getL();
            System.out.println("l: "+l);
            SecureNode node1= new SecureNode(p,g,l,"A","0");            
            SecureNode node2= new SecureNode(p,g,l,"B","1");
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
       
    }
    
}
