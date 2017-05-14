/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Networking;

import GUIInterface.Writable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.IOUtils;
import securechat.SecureNode;


/**
 *
 * @author sathya
 */
public class Client extends Thread {

    ServerSocket server;
    Thread client;
    int port;
    Writable writer;
    Server sender;
    SecureNode node;
    String otherIdentity = null;
    boolean IdentityReceived = false;
    boolean allLenREceived = false;
    boolean wroteToSig = false;
    boolean confirmIdentity = false;
    boolean finishWriting = false;
    boolean SigVerifiedFn = false;
    boolean lenReceived = false;
    byte[] PubToVerify;
    String MacToVerify;
    byte[] sigToVerify;
    boolean verified;
    boolean macVerified;
    byte[] iv;
    byte[] msg;
    int MsgLen;
    int idLen;
    int signLen;
    int pubLen;
    int hmacLen;

    public Client(int port, Writable toWrite) {
        this.port = port;
        this.writer = toWrite;
        try {
            server = new ServerSocket(port);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public Client(int port, Writable toWrite, Server ser, SecureNode d) {
        this.port = port;
        this.writer = toWrite;
        this.sender = ser;
        this.node = d;
        this.client = new Thread(this, "AKE");

        try {
            server = new ServerSocket(port);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void run() {
        Socket clientSocket;
        try {
            while ((clientSocket = server.accept()) != null) {
                InputStream is = clientSocket.getInputStream();
                byte[] bytes = IOUtils.toByteArray(is);
                String received = (new String(bytes, "UTF-8"));

                if (received != null) {
                    if (finishWriting && verified && !lenReceived && !allLenREceived) {
                        MsgLen = Integer.parseInt(received);
                        setLenReceived(true);
                    } else if (finishWriting && verified && lenReceived && !allLenREceived) {
                        setLenReceived(false);
                        File fileForIV = new File("./read_iv.txt");
                        if (fileForIV.createNewFile()) {
                            System.out.println("File is created!");
                        }
                        downloadFiles(bytes, fileForIV, MsgLen);
                        decryptMessage(received, (int) fileForIV.length());

                    } else if (received.contains("AKE")) {
                        this.node.setG_pow_y(new BigInteger(received.substring(3, received.length())));
                        this.node.setG_pow_y(this.node.getG_pow_y());
                        Calculateg_xy_mod();

                    } else if (!IdentityReceived) {
                        idLen = Integer.parseInt(received);
                        IdentityReceived = true;

                    } else {
                        if (!wroteToSig && !SigVerifiedFn && IdentityReceived) {
                            Hash_xy_mod();
                            signLen = Integer.parseInt(received);
                            wroteToSig = true;

                        } else if (wroteToSig && !finishWriting && !SigVerifiedFn && IdentityReceived) {
                            pubLen = Integer.parseInt(received);
                            SigVerifiedFn = true;

                        } else if (wroteToSig && !finishWriting && SigVerifiedFn && IdentityReceived && !allLenREceived) {
                            hmacLen = Integer.parseInt(received);
                            allLenREceived = true;
                        } else if (allLenREceived) {
                            File fileForall = new File("./entire_read.txt");
                            if (fileForall.createNewFile()) {
                                System.out.println("File is created!");
                            }
                            downloadFiles(bytes, fileForall, idLen + signLen + pubLen + hmacLen);

                            FileInputStream all = new FileInputStream("./entire_read.txt");
                            byte[] id = new byte[idLen];
                            all.read(id);
                            otherIdentity = (new String(id, "UTF-8"));
                            sigToVerify = new byte[signLen];
                            all.read(sigToVerify);
                            PubToVerify = new byte[pubLen];
                            all.read(PubToVerify);
                            verified = SignatureVerification();
                            byte[] hmac = new byte[hmacLen];
                            all.read(hmac);
                            MacToVerify = (new String(hmac, "UTF-8"));
                            finishWriting = verifyMac();
                            allLenREceived = false;
                            all.close();
                            
                            if(!verified || !finishWriting){
                                writer.write("BUMMMMMERRRRR");
                                System.exit(1);
                            }
                        }

                    }
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void initialise() {

        this.client.start();
    }

    public synchronized boolean isLenReceived() {
        return lenReceived;
    }

    public boolean verifyMac() {
        String data = null;
        boolean res = false;
        if (this.node.getMACip().equals("0")) {
            data = "1";
        } else {
            data = "0";
        }

        String me = Server.calculateHMAC(data.concat(otherIdentity), this.node.getMacKey()); //received 
        if (me.equals(MacToVerify)) {
            res = true;
        } else {
            res = false;
        }
        return res;
    }

    public synchronized void setLenReceived(boolean lenReceived) {
        this.lenReceived = lenReceived;
    }

    public void decryptMessage(String received, int len) {
        try {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            System.out.println("received time: " + timestamp);
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            loadIVAndMsg(len);
            SecretKeySpec myKey = new SecretKeySpec(this.node.getSessionKey(), "AES");
            this.node.setIv(iv);
            IvParameterSpec iv = new IvParameterSpec(this.node.getIv());
            c.init(Cipher.DECRYPT_MODE, myKey, iv);
            byte[] recoveredText = c.doFinal(msg);
            writer.write(new String(recoveredText));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void Calculateg_xy_mod() {
        this.node.setG_pow_modp(this.node.getG_pow_y().modPow(this.node.getX(), this.node.getP()));
        this.node.setX(BigInteger.ZERO);

    }

    public void Hash_xy_mod() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(this.node.getG_pow_modp().toByteArray());
            this.node.setHashed_key_128(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void PRF() {
        try {
            SecretKeySpec myKey = new SecretKeySpec(this.node.getHashed_key_128(), "AES");
            byte[] plainText = new byte[128];
            byte[] ones = new byte[16];
            Arrays.fill(ones, (byte) 1);

            SecureRandom random = new SecureRandom();
            byte IV[] = new byte[16];
            random.nextBytes(IV);
            IvParameterSpec iv = new IvParameterSpec(IV);
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, myKey, iv);
            byte[] macKey = new byte[c.getOutputSize(plainText.length)];
            c.doFinal(plainText, 0, plainText.length, macKey);    
            this.node.setMacKey(macKey);
            Cipher c1 = Cipher.getInstance("AES/CTR/NoPadding");
            c1.init(Cipher.ENCRYPT_MODE, myKey, iv);
            byte[] sessionKey = new byte[c1.getOutputSize(ones.length)];
            c1.doFinal(ones, 0, ones.length, sessionKey);
            this.node.setSessionKey(sessionKey);

        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ShortBufferException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void downloadFiles(byte[] bytes, File file, int BufLen) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            DataInputStream dis = new DataInputStream(bis);
            FileOutputStream fos = new FileOutputStream(file);
            byte[] buf = new byte[BufLen];
            int read = 0;
            while ((read = dis.read(buf)) != -1) {
                fos.write(buf);
            }
            fos.close();
            dis.close();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void loadIVAndMsg(int len) {
        try {
            FileInputStream IVMsg = new FileInputStream("./read_iv.txt");
            iv = new byte[16];
            IVMsg.read(iv);
            msg = new byte[IVMsg.available()];
            IVMsg.read(msg);
            IVMsg.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public boolean checkAgainstRT(int hash) {
        boolean res = false;
        if (hash == this.node.RT.get(otherIdentity)) {
            res = true;
        }
        System.out.println("result against RT:  " + res);
        return res;
    }

    public boolean SignatureVerification() {
        Signature sig = null;
        Boolean result = false;
        try {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(PubToVerify);
            KeyFactory keyFact = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubkeyToVerify = keyFact.generatePublic(pubKeySpec);
            confirmIdentity = checkAgainstRT(pubkeyToVerify.hashCode());
            sig = Signature.getInstance("SHA1withDSA", "SUN");
            sig.initVerify(pubkeyToVerify);

            byte[] g_pow_y_sign = this.node.getG_pow_y().toByteArray();
            byte[] g_pow_x_sign = this.node.getG_pow_x().toByteArray();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(g_pow_x_sign);
            outputStream.write(g_pow_y_sign);
            byte[] c = outputStream.toByteArray();

            sig.update(c);
            result = (sig.verify(sigToVerify));
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }
}
