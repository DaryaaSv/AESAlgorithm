package com.example.demo.JavaCode;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class AESCipher {

    public static String encrypt(String plaintext, String key, String iv, String mode) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS7Padding", "BC");

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        if(mode.equals("ecb")) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        String encrypted = Base64.getEncoder().encodeToString(encryptedBytes);

        return encrypted;
    }

    public static String decrypt(String encrypted, String key, String iv, String mode) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS7Padding", "BC");

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);

        if(mode.equals("ecb")) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }
        else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);

        return decrypted;
    }

}