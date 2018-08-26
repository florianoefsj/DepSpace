/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.confidentiality;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.n1analytics.paillier.EncodedNumber;
import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import com.n1analytics.paillier.cli.PrivateKeyJsonSerialiser;
import com.n1analytics.paillier.cli.SerialisationUtil;
import org.apache.commons.codec.binary.Base64;
/**
 *
 * @author eduardo
 */
public class OperableScheme {

    private static String comment = "key pair"; 

    public static PaillierPrivateKey generatePrivateKey(int keysize){
        return PaillierPrivateKey.create(keysize);        
    }
    
    public static byte[] privateKeyToBytes(PaillierPrivateKey privateKey){
        
        
        PrivateKeyJsonSerialiser serializedPrivateKey = new PrivateKeyJsonSerialiser(comment);
        privateKey.serialize(serializedPrivateKey);
        return serializedPrivateKey.toString().getBytes();
    }
    
    public static String privateKeyToString(PaillierPrivateKey privateKey){
        
        
        PrivateKeyJsonSerialiser serializedPrivateKey = new PrivateKeyJsonSerialiser(comment);
        privateKey.serialize(serializedPrivateKey);
        return serializedPrivateKey.toString();
    }
    
    public static PaillierPrivateKey stringToPrivateKey(String privateKey){
         ObjectMapper mapper = new ObjectMapper();
         try{
            java.util.Map privateKeyData = mapper.readValue(privateKey, java.util.Map.class);
            return SerialisationUtil.unserialise_private(privateKeyData);
         }catch(Exception e){
             e.printStackTrace();
             return null;
         }
           
    }
    
    public static PaillierPrivateKey bytesToPrivateKey(byte[] privateKey){
         ObjectMapper mapper = new ObjectMapper();
         try{
            java.util.Map privateKeyData = mapper.readValue(new String(privateKey), java.util.Map.class);
            return SerialisationUtil.unserialise_private(privateKeyData);
         }catch(Exception e){
             e.printStackTrace();
             return null;
         }
           
    }
    
    public static PaillierPublicKey generatePublicKey(PaillierPrivateKey privateKey){
        return privateKey.getPublicKey();
    }
    
    
    public static PaillierPublicKey bytesToPublicKey(byte[] publicKey){
        
        ObjectMapper mapper = new ObjectMapper();
         try{
            java.util.Map publicKeyData = mapper.readValue(new String(publicKey), java.util.Map.class);
            return SerialisationUtil.unserialise_public(publicKeyData);
         }catch(Exception e){
             e.printStackTrace();
             return null;
         }
        

    }
    
    
     public static PaillierPublicKey stringToPublicKey(String publicKey){
        
        ObjectMapper mapper = new ObjectMapper();
         try{
            java.util.Map publicKeyData = mapper.readValue(publicKey, java.util.Map.class);
            return SerialisationUtil.unserialise_public(publicKeyData);
         }catch(Exception e){
             e.printStackTrace();
             return null;
         }
        

    }
    
     public static String publicKeyToString(PaillierPublicKey publickey){
        //PublicKeyJsonSerialiser serialisedPublicKey = new PublicKeyJsonSerialiser(comment);
        //publickey.serialize(serialisedPublicKey);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        ObjectNode data = mapper.createObjectNode();
        data.put("alg", "PAI-GN1");
        data.put("kty", "DAJ");
        data.put("kid", comment);

        // Convert n to base64 encode
        String encodedModulus = new String(Base64.encodeBase64URLSafeString(publickey.getModulus().toByteArray()));
        data.put("n", encodedModulus);

        ArrayNode an = data.putArray("key_ops");
        an.add("encrypt");
        
        return data.toString();
    }
    
    
    public static byte[] publicKeyToBytes(PaillierPublicKey publickey){
        //PublicKeyJsonSerialiser serialisedPublicKey = new PublicKeyJsonSerialiser(comment);
        //publickey.serialize(serialisedPublicKey);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        ObjectNode data = mapper.createObjectNode();
        data.put("alg", "PAI-GN1");
        data.put("kty", "DAJ");
        data.put("kid", comment);

        // Convert n to base64 encode
        String encodedModulus = new String(Base64.encodeBase64URLSafeString(publickey.getModulus().toByteArray()));
        data.put("n", encodedModulus);

        ArrayNode an = data.putArray("key_ops");
        an.add("encrypt");
        
        return data.toString().getBytes();
    }
    
    
     public static String encryptedToString(EncryptedNumber enc){
         return SerialisationUtil.serialise_encrypted(enc).toString();
     }
     
      public static EncryptedNumber StringToEncrypted(String en, PaillierPublicKey pub){
           ObjectMapper mapper = new ObjectMapper();  
            try{
            java.util.Map enData = mapper.readValue(en, java.util.Map.class);
            return SerialisationUtil.unserialise_encrypted(enData,pub);
         }catch(Exception e){
             e.printStackTrace();
             return null;
         }
      }
    
      
      public static EncryptedNumber add(EncryptedNumber enc1, EncryptedNumber enc2) {
        return enc1.add(enc2);
      }
      
      
      public static EncryptedNumber add(EncryptedNumber enc, double value) {
        return enc.add(value);
      }
      
      public static EncryptedNumber multiply(EncryptedNumber enc, double value) {
        return enc.multiply(value);
      }
    
    public static EncryptedNumber encrypt(PaillierPublicKey pub, String plaintext) {
      

        PaillierContext c = pub.createSignedContext();

        return c.encrypt(Double.parseDouble(plaintext));

    }

    
    
    public static double decrypt(PaillierPrivateKey priv, EncryptedNumber enc){

       EncodedNumber encoded = priv.decrypt(enc);
      
       return encoded.decodeDouble();
    }       
    
}