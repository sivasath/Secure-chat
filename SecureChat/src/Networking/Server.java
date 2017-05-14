/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Networking;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.commons.codec.binary.Base64;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.util.Formatter;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import securechat.Main;
import securechat.SecureNode;

/**
 *
 * @author sathya
 */
public class Server implements Runnable {

    int port;
    String Ip;
    String message;
    Boolean AKE = false;
    BigInteger g;
    BigInteger p;
    Random x = new Random();
    Boolean suspended = false;
    SecureNode d;
    Thread t;
    Boolean isResumed = false;

    public Server(int port, String Ip, String message, SecureNode node) {
        this.port = port;
        this.Ip = Ip;
        this.message = message;
        this.AKE = false;
        this.d = node;
    }

    public Server(int port, String Ip) {
        this.port = port;
        this.Ip = Ip;
        this.AKE = true;
    }

    public Server(int port, String Ip, SecureNode node) {
        this.port = port;
        this.Ip = Ip;
        this.AKE = true;
        this.d = node;
    }

    public void run() {

        if (this.AKE == false) {
            byte[] cipherText = encryptMessage();

        } else {
            try {
                if (!this.isResumed) {

                    Socket serverSocket = new Socket(this.Ip, this.port);
                    this.g = this.d.getG();
                    String toSend = "AKE" + (this.d.getG_pow_x());
                    serverSocket.getOutputStream().write(toSend.getBytes());
                    serverSocket.close();
                } else {
                    //signature
                    File file = new File("./write.txt");
                    File file1 = new File("./write_pub.txt");
                    if (file.createNewFile()) {
                        System.out.println("File is created!");
                    }
                    if (file1.createNewFile()) {
                        System.out.println("File is created!");
                    }
                    signDSA();

                    //MAC
                    String hmac;
                    hmac = calculateHMAC(this.d.getMACip().concat(this.d.getIdentity()), this.d.getMacKey());

                    //combining
                    sendMesLen(this.d.identity.getBytes().length);
                    sendMesLen(this.d.getSign().length);
                    sendMesLen(this.d.getPub().getEncoded().length);
                    sendMesLen(hmac.getBytes().length);
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(this.d.identity.getBytes());
                    outputStream.write(this.d.getSign());
                    outputStream.write(this.d.getPub().getEncoded());
                    outputStream.write(hmac.getBytes());
                    
                    byte[] c = outputStream.toByteArray();
                    File f = new File("./entire.txt");
                    if (f.createNewFile()) {
                        System.out.println("File is created!");
                    }
                    writeToFiles(f, c);
                    sendFiles(f);

                }
            } catch (IOException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

    }

    public void setSuspended() {
        this.suspended = true;

    }

    public void initialise() {
        if (t == null) {
            t = new Thread(this, "AKE");
            t.start();
        } else {
            this.isResumed = true;
            run();
        }
    }

    public static String calculateHMAC(String data, byte[] key) {
        Mac mac = null;
        byte[] res = null;
        try {
            SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
            mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            res = (mac.doFinal(data.getBytes()));

        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
        return toHexString(res);
    }

    public void suspendThread() {
        try {
            wait();
            this.suspended = true;
        } catch (InterruptedException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void resumeThread() {
        notify();
        this.suspended = false;
        run();
    }

    /* ref to http://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays */
    public void signDSA() {
        try {
            byte[] g_pow_y_sign = this.d.getG_pow_y().toByteArray();
            byte[] g_pow_x_sign = this.d.getG_pow_x().toByteArray();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(g_pow_y_sign);
            outputStream.write(g_pow_x_sign);
            byte[] c = outputStream.toByteArray();
            this.d.getDsa().update(c);
            this.d.setSign(this.d.getDsa().sign());
        } catch (SignatureException | IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void writeToFiles(File file, byte[] toSend) {
        try {

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

    public void sendFiles(File file) {
        try {
            byte[] sig_bytes = new byte[(int) file.length()];
            BufferedInputStream bis1 = new BufferedInputStream(new FileInputStream(file));
            bis1.read(sig_bytes, 0, sig_bytes.length);
            Socket writeSocket = new Socket(Ip, port);
            writeSocket.getOutputStream().write(sig_bytes, 0, sig_bytes.length);
            writeSocket.getOutputStream().flush();
            writeSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public byte[] encryptMessage() {
        byte[] cipherText = null;
        byte[] text = null;
        try {

            byte[] plainText = message.getBytes();

            SecretKeySpec myKey;
            myKey = new SecretKeySpec(this.d.getSessionKey(), "AES");

            SecureRandom random = new SecureRandom();
            byte randombytes[] = new byte[16];
            random.nextBytes(randombytes);
            this.d.setIv(randombytes);

            IvParameterSpec iv = new IvParameterSpec(this.d.getIv());
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, myKey, iv);
            cipherText = new byte[c.getOutputSize(plainText.length)];
            c.doFinal(plainText, 0, plainText.length, cipherText);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(iv.getIV());
            outputStream.write((cipherText));
            text = outputStream.toByteArray();

            File ivMsgFile = new File("./write_iv.txt");
            if (ivMsgFile.createNewFile()) {
                System.out.println("File is created!");
            }

            FileOutputStream sigfos = new FileOutputStream(ivMsgFile);
            sigfos.write(text);
            sigfos.flush();
            sigfos.close();

            byte[] sig_bytes = new byte[(int) ivMsgFile.length()];
            BufferedInputStream bis1 = new BufferedInputStream(new FileInputStream(ivMsgFile));
            bis1.read(sig_bytes, 0, sig_bytes.length);

            sendMesLen((int) ivMsgFile.length());
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            System.out.println("sent time: " + timestamp);
            Socket writeSocket = new Socket(Ip, port);
            writeSocket.getOutputStream().write(sig_bytes, 0, sig_bytes.length);
            writeSocket.getOutputStream().flush();
            writeSocket.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException | BadPaddingException | IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
        return Base64.encodeBase64(text);
    }

    public void sendMesLen(int len) {
        try {
            String numberAsString = String.valueOf(len);
            try (Socket serverSocket = new Socket(Ip, port)) {
                serverSocket.getOutputStream().write(numberAsString.getBytes());
            }
        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }
}
