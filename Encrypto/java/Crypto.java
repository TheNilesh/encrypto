import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class Crypto {

	public static void main(String args[]) throws Exception{
		String password="myPassword";
		byte[] salt=new byte[]{1,5,7,3,2,1};
		
		//sender
		Crypto c=new Crypto(password.toCharArray(),salt);
		//send(c.getIv());   send Iv to receiver
		//send encrypted messages
		String ct=c.encrypt("my_pLaInTeXt");
		System.out.println("CT:" + ct);
		
		//receiver
		byte[] iv=c.getIv();	//get Iv from sender
		Crypto d=new Crypto(password.toCharArray(),salt,iv);
		System.out.println("PT:" + d.decrypt(ct));
		
	}

	Cipher cipher;
	byte[] iv;
	
	public Crypto(char[] password,byte[] salt,byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException{
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		if(iv==null){	//this object is intended to encrypt
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			AlgorithmParameters params = cipher.getParameters();
			this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		}else{
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
		}
	}
	
	public Crypto(char[] password,byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException{
		this(password,salt,null);
	}	
	
	public byte[] encrypt(byte[] plaintext) throws InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		byte[] ciphertext = cipher.doFinal(plaintext);
		return ciphertext;
	}
	
	public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException{
		byte[] plaintext=cipher.doFinal(ciphertext);
		return plaintext;
	}
	
	public String encrypt(String plaintext) throws InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		byte[] pt=plaintext.getBytes();
		byte[] ct=encrypt(pt);
		return toBase64(ct);
	}
	
	public String decrypt(String ciphertext) throws IllegalBlockSizeException, BadPaddingException{
		byte[] ct=base64ToBytes(ciphertext);
		byte[] pt=decrypt(ct);
		return new String(pt);
	}
	
	private String toBase64(byte[] b){
		return Base64.getEncoder().encodeToString(b);
	}
	
	private byte[] base64ToBytes(String inputText){
		return Base64.getDecoder().decode(inputText);
	}
	
	public byte[] getIv(){
		return iv;
	}
}
