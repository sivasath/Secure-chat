package securechat;

import GUI.ChatBox;
import Networking.Client;
import Networking.Server;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author sathya
 */
public class SecureNode {

    public Map<String, Integer> RT = new HashMap<String, Integer>();
    byte[] SessionKey = new byte[16];
    byte[] macKey = new byte[128];
    PrivateKey priv;
    PublicKey pub;
    BigInteger y;
    KeyPair pair;
    BigInteger g;
    BigInteger p;
    BigInteger x;
    BigInteger g_pow_modp;
    BigInteger g_pow_x;
    BigInteger g_pow_y;
    byte[] hashed_key_128;
    public String Ipaddr;
    public String receivPort;
    public String SenderPort;
    public String identity;
    public byte[] sign;
    String MACip;
    byte[] iv = new byte[16];
    Signature dsa;
    int l;
    BigInteger ConcatednatedInputForSigning;

    public SecureNode(BigInteger p_common, BigInteger g_common, int l, String id, String MACip) throws InvalidParameterSpecException {

        RT.put("A", 1984236);
        RT.put("B", 1985567);
        RT.put("C", 125);
        RT.put("D", 126);
        RT.put("E", 127);
        RT.put("F", 128);
        this.identity = id;
        this.g = g_common;
        this.p = p_common;
        this.l = l;
        this.MACip = MACip;
        generateG_pow_x_modp();
        setUpDSA();
        initiateGUI();
    }   

    public void initiateGUI() {
        ChatBox application = new ChatBox(this);
        application.show();
    }

    public void generateG_pow_x_modp() {
        String toSend = null;
        SecureRandom random = new SecureRandom();
        byte randombytes[] = new byte[this.l];
        random.nextBytes(randombytes);
        this.setX(new BigInteger(randombytes));
        this.setG_pow_x(this.g.modPow(this.getX(),this.getP()));
        System.out.println("x len: "+this.getX());

    }

    public void setUpDSA() {
        try {
            File file = null;
            //only for testing on the same machine otherwise if/else not necessary
            if (this.identity.equals("A")) {
                file = new File("./Private_key_A.txt");
            } else {
                file = new File("./Private_key_B.txt");
            }
            if (file.createNewFile()){
	        System.out.println("File is created!");
	      }

            BufferedReader br = new BufferedReader(new FileReader(file));
            if (br.readLine() == null) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                random.nextInt(this.l);
                keyGen.initialize(1024, random);
                this.pair = keyGen.generateKeyPair();
                this.priv = pair.getPrivate();
                this.pub= pair.getPublic();
                
                

                writeToFiles("priv", this.priv.getEncoded(), this.identity);
                writeToFiles("pub", this.pub.getEncoded(), this.identity);
            } else {
                loadPriv(this.identity);
                loadPub(this.identity);
            }
            System.out.println(" pub key hashcode: "+this.identity+": "+this.pub.hashCode());
            System.out.println("Private key: " + this.priv);
            System.out.println("Pub key: " + this.pub);
            this.dsa = Signature.getInstance("SHA1withDSA", "SUN");
            this.dsa.initSign(this.priv);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public Map<String, Integer> getRT() {
        return RT;
    }

    public void setRT(Map<String, Integer> RT) {
        this.RT = RT;
    }

    public static void writeToFiles(String type, byte[] toSend, String id) {
        File file = null;
        try {
            if (type.equals("priv")) {
                if (id.equals("A")) {
                    file = new File("./Private_key_A.txt");
                } else {
                    file = new File("./Private_key_B.txt");
                }
            } else {
                if (id.equals("A")) {
                    file = new File("./Public_key_A.txt");
                } else {
                    file = new File("./Public_key_B.txt");
                }
            }
            if (file.createNewFile()){
	        System.out.println("File is created!");
	      }

            FileOutputStream sigfos = new FileOutputStream(file);
            sigfos.write(toSend);
            sigfos.flush();
            sigfos.close();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void loadPub(String id) {
        File file = null;
        byte[] temp = null;
        FileInputStream pub = null;
        try {
            if (id.equals("A")) {
                pub = new FileInputStream("./Public_key_A.txt");
            } else {
                pub = new FileInputStream("./Public_key_B.txt");
            }
            

            temp = new byte[pub.available()];
            pub.read(temp);
            pub.close();
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(temp);
            this.pub = keyFactory.generatePublic(publicKeySpec);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void loadPriv(String id) {
        File file = null;
        byte[] temp = null;
        FileInputStream priv = null;
        try {
            if (id.equals("A")) {
                priv = new FileInputStream("./Private_key_A.txt");
            } else {
                priv = new FileInputStream("./Private_key_B.txt");
            }
            

            temp = new byte[priv.available()];
            priv.read(temp);
            priv.close();
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(temp);
            this.priv = keyFactory.generatePrivate(privateKeySpec);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(SecureNode.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public byte[] getSessionKey() {
        return SessionKey;
    }

    public void setSessionKey(byte[] SessionKey) {
        this.SessionKey = SessionKey;
    }

    public PrivateKey getPriv() {
        return priv;
    }

    public void setPriv(PrivateKey priv) {
        this.priv = priv;
    }

    public PublicKey getPub() {
        return pub;
    }

    public void setPub(PublicKey pub) {
        this.pub = pub;
    }

    public BigInteger getY() {
        return y;
    }

    public String getMACip() {
        return MACip;
    }

    public void setMACip(String MACip) {
        this.MACip = MACip;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    public byte[] getHashed_key_128() {
        return hashed_key_128;
    }

    public void setHashed_key_128(byte[] hashed_key_128) {
        this.hashed_key_128 = hashed_key_128;
    }

    public BigInteger getConcatednatedInputForSigning() {
        return ConcatednatedInputForSigning;
    }

    public void setConcatednatedInputForSigning(BigInteger ConcatednatedInputForSigning) {
        this.ConcatednatedInputForSigning = ConcatednatedInputForSigning;
    }

    public KeyPair getPair() {
        return pair;
    }

    public void setPair(KeyPair pair) {
        this.pair = pair;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    public BigInteger getG_pow_x() {
        return g_pow_x;
    }

    public void setG_pow_x(BigInteger g_pow_x) {
        this.g_pow_x = g_pow_x;
    }

    public BigInteger getG_pow_y() {
        return g_pow_y;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    public BigInteger getG_pow_modp() {
        return g_pow_modp;
    }

    public void setG_pow_modp(BigInteger g_pow_modp) {
        this.g_pow_modp = g_pow_modp;
    }

    public void setG_pow_y(BigInteger g_pow_y) {
        this.g_pow_y = g_pow_y;
    }

    public String getIpaddr() {
        return Ipaddr;
    }

    public void setIpaddr(String Ipaddr) {
        this.Ipaddr = Ipaddr;
    }

    public String getReceivPort() {
        return receivPort;
    }

    public void setReceivPort(String receivPort) {
        this.receivPort = receivPort;
    }

    public String getSenderPort() {
        return SenderPort;
    }

    public void setSenderPort(String SenderPort) {
        this.SenderPort = SenderPort;
    }

    public String getIdentity() {
        return identity;
    }
    

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public Signature getDsa() {
        return dsa;
    }

    public void setDsa(Signature dsa) {
        this.dsa = dsa;
    }

    public int getL() {
        return l;
    }

    public void setL(int l) {
        this.l = l;
    }

}
