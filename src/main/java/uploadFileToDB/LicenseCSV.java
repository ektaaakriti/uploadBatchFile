package uploadFileToDB;

import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;
import org.supercsv.cellprocessor.constraint.NotNull;
import org.supercsv.cellprocessor.ift.CellProcessor;
import org.supercsv.io.CsvBeanReader;
import org.supercsv.io.ICsvBeanReader;
import org.supercsv.prefs.CsvPreference;

public class LicenseCSV {
	
	static connectToDb DB=new connectToDb();
	static Connection dbcon=DB.connect_db();
	static Properties properties = DB.getProperties();
	 static String csvFilePath="";
	public int ReadLicense(int i) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		
		  try {
			 
		 csvFilePath =properties.getProperty("csvPathLicense");
	   int batchSize = 100;
int validity=validity();
	   

	   ICsvBeanReader beanReader = null;
	   CellProcessor[] processors = new CellProcessor[] {
	           new NotNull(),
	           new NotNull(), 
	          
	           
	   
	   };

	 
	       long start = System.currentTimeMillis();

	       
	       dbcon.setAutoCommit(false);

	       String sql = "INSERT INTO license_details(ip,start_date,end_date,status_flag) VALUES (?,?, ?, ?)";
	       PreparedStatement statement = dbcon.prepareStatement(sql);

	       beanReader = new CsvBeanReader(new FileReader(csvFilePath), CsvPreference.STANDARD_PREFERENCE);
	      
	       beanReader.getHeader(true); // skip header line

	       String[] header = {"ip","Start_date"};
	       Users bean = null;

	       int count = 0;
	       int license_number=0;
	       System.out.println("Dummy3");
	       int remain=remaining_license();
	   	System.out.println("Dummy411");
	       while ((bean = beanReader.read(Users.class, header, processors)) != null) {
	    	   if(remain>license_number) {
	    		 	System.out.println("Dummy4112");	   
	       	String ip=bean.getIp();
	       	String start_date=bean.getStart_date();
	     	System.out.println("Dummy41131");
	         String Eip=encryptnew(ip);
	         System.out.println("Dummy4113");
	         String Estart_date=encryptnew(start_date);
	         System.out.println(start_date);
	         start_date=start_date.replace("/","-");
	         String[] stdt=start_date.split("-",3);
	    	 String year=stdt[2];
	    	 int year1=Integer.parseInt(year);
	    	 System.out.println("Dummy11");
	    	 int endyear=year1+validity;
	    	 System.out.println("Dummy31");
	    	 String endyr=Integer.toString(endyear);
	    	  start_date=stdt[2]+"-"+stdt[1]+"-"+stdt[0];
	    	// String Enddate=stdt[0]+"-"+stdt[1]+"-"+endyr;
	    	 String Enddate=endyr+"-"+stdt[1]+"-"+stdt[0];
	    	 System.out.println(Enddate);
	    	 System.out.println("Dummy41");
	    	 String enddate=encryptnew(Enddate);
	    	 String status=encryptnew("activated");
	    	 System.out.println(ip);
	    	 System.out.println(start_date);
	    	 System.out.println(enddate);
	    	 System.out.println(status);
	    	// String status=encrypt1("activated");
	           statement.setString(1,Eip);
	           statement.setString(2,Estart_date);
	           statement.setString(3,enddate);
	           statement.setString(4,status);
	    	/* statement.setString(1,ip);
	           statement.setString(2,start_date);
	           statement.setString(3,Enddate);
	           statement.setString(4,status);*/
	          
	           statement.addBatch();}
	    	   
	    	   else {
	    		   System.out.println("license number extended");
	    	   }
	    	   license_number++;
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
	      // dbcon.close();

	       long end = System.currentTimeMillis();
	       System.out.println("Execution Time: " + (end - start));
	   } catch (IOException ex) {
	       System.err.println(ex);
	       DB.moveFile(i,csvFilePath);
	   } catch (SQLException ex) {
	       ex.printStackTrace();
	       DB.moveFile(i,csvFilePath);

	       try {
	           dbcon.rollback();
	           
	       } catch (SQLException e) {
	           e.printStackTrace();
	           DB.moveFile(i,csvFilePath);
	       }
	   }
	  DB.moveFile(i,csvFilePath);
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
	        System.out.println("in encrypt 0");
	        final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, salt, password.getBytes(StandardCharsets.UTF_8),
	                MessageDigest.getInstance("MD5"));
	       if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	            // insert at specific position
	            Security.insertProviderAt(new BouncyCastleProvider(), 1);
	        } System.out.println("in encrypt 1");
	      //  Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        System.out.println("in encrypt 2");
	        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyAndIV[0], "AES"), new IvParameterSpec(keyAndIV[1]));
	        byte[] encryptedData = cipher.doFinal(stringToEncrypt.getBytes(StandardCharsets.UTF_8));
	        System.out.println("in encrypt 3");
	        byte[] prefixAndSaltAndEncryptedData = new byte[16 + encryptedData.length];
	        // Copy prefix (0-th to 7-th bytes)
	        System.arraycopy("Salted__".getBytes(StandardCharsets.UTF_8), 0, prefixAndSaltAndEncryptedData, 0, 8);
	        // Copy salt (8-th to 15-th bytes)
	        System.arraycopy(salt, 0, prefixAndSaltAndEncryptedData, 8, 8);
	        // Copy encrypted data (16-th byte and onwards)
	        System.out.println("in encrypt 4");
	        System.arraycopy(encryptedData, 0, prefixAndSaltAndEncryptedData, 16, encryptedData.length);
	        return org.apache.commons.codec.binary.Base64.encodeBase64String(prefixAndSaltAndEncryptedData);
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}
	 public static int validity() {
		  String validity="";
		  int divalidity=0;
		 try {
				java.sql.Statement stmt1 = dbcon.createStatement();
				
				ResultSet rs1 = stmt1.executeQuery("select * from license_data ");
				
				while (rs1.next()) {
					
			 validity=rs1.getString("validity");
					
			 System.out.println("encrypted validity"+validity);	
			
					}
				rs1.close();	
				String dvalidity=decryptnew(validity);
				System.out.println("decrypted validity string"+divalidity);
				divalidity=Integer.parseInt(dvalidity);
				System.out.println("decryptted validity integer"+divalidity);
			}
		 
			catch (Exception e) {
			System.out.println("errro in finding validity of license");	
			}
			return divalidity;
		
		 
	 }
	 public static int total_license() {
		  String total="";
		  int total2=0;
		 try {
				java.sql.Statement stmt1 = dbcon.createStatement();
				
				ResultSet rs1 = stmt1.executeQuery("select * from license_data ");
				
				while (rs1.next()) {
					
			 total=rs1.getString("total_license");
					
			 System.out.println("Total license enc"+total);
			
					}
				rs1.close();	
				String total1=decryptnew(total);
				 System.out.println("Total license dec"+total1);
				total2=Integer.parseInt(total1);
				System.out.println("total license int"+total2);
			}
		 
			catch (Exception e) {
			System.out.println("Error in finding total license");	
			}
			return total2;
		
		 
	 }
	 public static int remaining_license() {
		 // String validity="";
		 int used1 = 0;
		  int remaining1 = 0;
		 try {
				java.sql.Statement stmt12 = dbcon.createStatement();
				System.out.println("dummy23");
				ResultSet rs2= stmt12.executeQuery("select count(*) from license_details");
			//	ResultSet rs = stmt.executeQuery("select count(*) from MyPlayers");
				
				while (rs2.next()) {
					
			 used1=rs2.getInt("count(*)");
				System.out.println("used license are "+used1);
					
			
				}
				rs2.close();	
		 
			int total1=total_license();
			System.out.println("total license ares "+total1);
			 remaining1=total1-used1;		
			System.out.println("remaining license ares"+remaining1);
			}
		 
			catch (Exception e) {
			System.out.println("ERROR IN FINDING REMAINING LICENSE");	
			}
		// return used1;
			return remaining1;
		
		 
	 }
	 
}

