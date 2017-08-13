package org.yajin.android_forensics.tools;

import java.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * On Samsung devices, username and password in database
 * (/data/data/com.android.email/databases/EmailProvider.db) are encrypted,
 * which is different from official Android version.
 * 
 * It uses AES encryption with a salt value. Fortunately (or unfortunately) the salt
 * value is fixed for all devices :).
 * 
 * This program has been verified on S3 with Android version 4.1.2
 * 
 * */

public class DecryptSamsungEmailPassword {

	private static SecretKeySpec getSecretKey(String str, String salt) {
		
		char[] bstr = str.toCharArray();
		byte[] bsalt = salt.getBytes(); 
		
		PBEKeySpec keyspec = new PBEKeySpec(bstr, bsalt, 0x64, 0x80);
		
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			
			SecretKey key = factory.generateSecret(keyspec);
			
			return new SecretKeySpec(key.getEncoded(), "AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}
	
	
	private static String decrypt(String encodedPassword) {
		
		byte[] iv = new byte[16];
		
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		SecretKeySpec seckey = getSecretKey("(qlBxn2qlB!ro@qkf?)", "samsung_sec_salt");
		
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			cipher.init(2, seckey, ivspec);
			
			byte[] dd = Base64.getDecoder().decode(encodedPassword);
			
			dd = cipher.doFinal(dd);
			
			return new String(dd);
						
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		if (args.length != 1) {
			System.out.printf("Useage: ./program  encrypted_string ");
			return;
		}
		
		String plaintext = decrypt(args[0]);

		System.out.printf("["+args[0]+"] -> [" + plaintext + "]" );
	}

}
