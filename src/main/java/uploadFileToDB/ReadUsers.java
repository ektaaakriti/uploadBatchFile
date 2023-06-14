package uploadFileToDB;

import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.supercsv.cellprocessor.constraint.NotNull;
import org.supercsv.cellprocessor.ift.CellProcessor;
import org.supercsv.io.CsvBeanReader;
import org.supercsv.io.ICsvBeanReader;
import org.supercsv.prefs.CsvPreference;

public class ReadUsers {
	static String csvFilePath ="";
	static connectToDb DB=new connectToDb();
	static Connection dbcon=DB.connect_db();
	static Properties properties = DB.getProperties();
	public int Users(int i) {
	
 
	  csvFilePath =properties.getProperty("csvpathUsers");
   int batchSize = 20;

   

   ICsvBeanReader beanReader = null;
   CellProcessor[] processors = new CellProcessor[] {
           new NotNull(),
           new NotNull(), 
           new NotNull(),
           new NotNull(),
           new NotNull(),
           new NotNull(), 
           new NotNull(),
           new NotNull(),
           new NotNull(),
           new NotNull(), 
           new NotNull(),
           new NotNull(),
           new NotNull(),
           new NotNull(), 
           new NotNull(),
           new NotNull(),
           
           
   
   };

   try {
       long start = System.currentTimeMillis();

       
       dbcon.setAutoCommit(false);

       String sql = "INSERT INTO Users(First_Name, Last_Name, AD_User_login_ID, Password_enc, Mobile, Email_ID, Password, Department, Location, Manager_Name, Manager_User_ID, Emp_Code, username, User_Type, user_group_id,user_id) VALUES (?, ?, ?, ?,?, ?, ?, ?,?, ?, ?, ?,?, ?,?,?)";
       PreparedStatement statement = dbcon.prepareStatement(sql);

       beanReader = new CsvBeanReader(new FileReader(csvFilePath), CsvPreference.STANDARD_PREFERENCE);
      
       beanReader.getHeader(true); // skip header line

       String[] header = {"First_Name","Last_Name","AD_User_login_ID","Password_enc","Mobile","Email_ID","Password","Department","Location","Manager_Name","Manager_User_ID","Emp_Code","username","User_Type","user_group_id","user_id"};
       Users bean = null;

       int count = 0;

       while ((bean = beanReader.read(Users.class, header, processors)) != null) {
       	 String First_Name =bean.getFirst_Name();
            String Last_Name =bean.getLast_Name();	
            String AD_User_login_ID=bean.getAD_User_login_ID();
           String Password_enc=encryptnew(bean.getPassword_enc());
           String Mobile=bean.getMobile();
           String Email_ID=bean.getEmail_ID();
           String Password=encryptnew(bean.getPassword());
           String Department=bean.getDepartment();
           String Location=bean.getLocation();
           String Manager_Name=bean.getManager_Name();
           String Manager_User_ID=bean.getManager_User_ID();
            String Emp_Code=bean.getEmp_Code();
           String username=bean.getUsername();
        //   String admin_panel_enable=bean.getAdmin_panel_enable();
           String user_group_id=bean.getUser_group_id();
           String user_id=bean.getUser_id();
           String user_type=bean.getUser_Type();
           

           statement.setString(1,First_Name);
           statement.setString(2,Last_Name);
           statement.setString(3,AD_User_login_ID);
           statement.setString(4,Password_enc);
           statement.setString(5,Mobile);
           statement.setString(6,Email_ID);
           statement.setString(7,Password);
           statement.setString(8,Department);
           statement.setString(9,Location);
           statement.setString(10, Manager_Name);
           statement.setString(11,Manager_User_ID);
           statement.setString(12,Emp_Code);
           statement.setString(13,username);
           statement.setString(14,user_type);
           statement.setString(15,user_group_id);
           statement.setString(16, user_id);
          
           statement.addBatch();

           if (count % batchSize == 0) {
               statement.executeBatch();
               count++;
           }
           i++;
           
       }

       beanReader.close();

       // execute the remaining queries
       statement.executeBatch();

       dbcon.commit();
      

       long end = System.currentTimeMillis();
       System.out.println("Execution Time: " + (end - start));
   } catch (IOException ex) {
	   DB.moveFile(i,csvFilePath );
       System.err.println(ex);
   } catch (SQLException ex) {
	   DB.moveFile(i,csvFilePath );
       ex.printStackTrace();
       try {
           dbcon.rollback();
           
       } catch (SQLException e) {
           e.printStackTrace();
           DB.moveFile(i,csvFilePath);
       }
      
   }


  DB.moveFile(i,csvFilePath );
return i;
}
	public static byte[][] GenerateKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) {
	    int digestLength = md.getDigestLength();
	    int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
	    byte[] generatedData = new byte[requiredLength];
	    int generatedLength = 0;
	    try {
	        md.reset();
	        // Repeat process until sufficient data has been generated
	        while (generatedLength < keyLength + ivLength) {
	            // Digest data (last digest if available, password data, salt if available)
	            if (generatedLength > 0)
	                md.update(generatedData, generatedLength - digestLength, digestLength);
	            md.update(password);
	            if (salt != null)
	                md.update(salt, 0, 8);
	            md.digest(generatedData, generatedLength, digestLength);
	            // additional rounds
	            for (int i = 1; i < iterations; i++) {
	                md.update(generatedData, generatedLength, digestLength);
	                md.digest(generatedData, generatedLength, digestLength);
	            }
	            generatedLength += digestLength;
	        }
	        // Copy key and IV into separate byte arrays
	        byte[][] result = new byte[2][];
	        result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
	        if (ivLength > 0)
	            result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);
	        return result;
	    } catch (DigestException e) {
	        throw new RuntimeException(e);
	    } finally {
	        // Clean out temporary data
	        Arrays.fill(generatedData, (byte)0);
	    }
	}

	public static String decryptnew(String encrypted) throws InvalidAlgorithmParameterException,
	InvalidKeyException,
	BadPaddingException, 
	IllegalBlockSizeException,
	NoSuchAlgorithmException,
	NoSuchPaddingException {
	 String secret = "1234567890123456";
	 String cipherText = encrypted;	    
	 byte[] ciphertextData = org.apache.commons.codec.binary.Base64.decodeBase64(cipherText);
	 byte[] saltData = Arrays.copyOfRange(ciphertextData, 8, 16);
	 MessageDigest md5 = MessageDigest.getInstance("MD5");
	 final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
	 SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
	 IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
	    // get encrypted data without iv
	    byte[] encrypted1 = Arrays.copyOfRange(ciphertextData, 16, ciphertextData.length);
	    Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
	    byte[] decryptedData = aesCBC.doFinal(encrypted1);
	    String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);	        
	    return decryptedText;

	}
	public static String encryptnew(String stringToEncrypt) {
	    try {
	       // String stringToEncrypt = "Hello world 12345";
	        String password = "1234567890123456";
	        SecureRandom sr = new SecureRandom();
	        byte[] salt = new byte[8];
	        sr.nextBytes(salt);
	        final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, salt, password.getBytes(StandardCharsets.UTF_8),
	                MessageDigest.getInstance("MD5"));
	        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	            // insert at specific position
	            Security.insertProviderAt(new BouncyCastleProvider(), 1);
	        }
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyAndIV[0], "AES"), new IvParameterSpec(keyAndIV[1]));
	        byte[] encryptedData = cipher.doFinal(stringToEncrypt.getBytes(StandardCharsets.UTF_8));
	        byte[] prefixAndSaltAndEncryptedData = new byte[16 + encryptedData.length];
	        // Copy prefix (0-th to 7-th bytes)
	        System.arraycopy("Salted__".getBytes(StandardCharsets.UTF_8), 0, prefixAndSaltAndEncryptedData, 0, 8);
	        // Copy salt (8-th to 15-th bytes)
	        System.arraycopy(salt, 0, prefixAndSaltAndEncryptedData, 8, 8);
	        // Copy encrypted data (16-th byte and onwards)
	        System.arraycopy(encryptedData, 0, prefixAndSaltAndEncryptedData, 16, encryptedData.length);
	        return org.apache.commons.codec.binary.Base64.encodeBase64String(prefixAndSaltAndEncryptedData);
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}
}


