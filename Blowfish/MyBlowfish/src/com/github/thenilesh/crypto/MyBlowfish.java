package com.github.thenilesh.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

class MyBlowfish {
    public String encrypt(String plaintext, String key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] cipherTextBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encodeBase64(cipherTextBytes), StandardCharsets.UTF_8);
    }

    public String decrypt(String ciphertext, String key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] cipherTextBytes = Base64.decodeBase64(ciphertext);
        byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
        return new String(plainTextBytes, StandardCharsets.UTF_8);
    }
    
    public static void main(String[] args) throws Exception {
		MyBlowfish b = new MyBlowfish();
		String ct = b.encrypt("nilesh", "12345678");
		System.out.println(ct);
	}
}
