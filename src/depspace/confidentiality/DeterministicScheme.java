/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.confidentiality;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 *
 * @author Edson Floriano
 */
public class DeterministicScheme {
    
    public static String Det_keygenerate (int size){
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[size];
        random.nextBytes(bytes);
        return bytes.toString();
    }
    
    public static String HmacSHA256Str(String data, String key) throws Exception{
        byte[] keyBytes = key.getBytes("UTF-8");
        return HmacSHA256Str(data, keyBytes);
    }
    
    public static String HmacSHA256Str(String data, byte[] keyBytes) throws Exception{
        byte[] hmac = HmacSHA256(data, keyBytes);
        String c = new String();
        for (int i=0; i<hmac.length; i++)
            if (i==hmac.length - 1)
                c = c+hmac[i];
            else
                c = c+hmac[i]+" ";
        
        
        
        return c;
    }
    
    public static byte[] HmacSHA256(String data, byte[] keyBytes) throws Exception {
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(keyBytes, algorithm));
        byte[] hmac = mac.doFinal(data.getBytes("UTF-8"));
        return hmac;
    }
    
    public static byte[] getSecretKey(String key, int keysize) throws Exception{
        //Gerando Hash da chave
        MessageDigest algorithm = MessageDigest.getInstance("SHA-256");
        algorithm.reset();
        algorithm.update(key.getBytes("UTF-8"));
        
        byte[] sk = algorithm.digest();
        BigInteger bigInt_sk = new BigInteger(1,sk);
        String sk_str = bigInt_sk.toString(16);
        
        byte[] skBytes = sk_str.getBytes("UTF-8");
        skBytes = Arrays.copyOf(skBytes, keysize);
        
        return skBytes;
    }
    
    public static String encryptedToString(byte[] hmac, byte[] cypher) throws Exception{
        String c = new String();
            for (int i=0; i<hmac.length; i++)
                if (i==hmac.length - 1)
                    c = c+hmac[i];
                else
                    c = c+hmac[i]+" ";
            c = c+";";
            for (int i=0; i<cypher.length; i++)
                if (i==cypher.length - 1)
                    c = c+cypher[i];
                else
                    c = c+cypher[i]+" ";
        return c;
    }
    
    public static String DetEncrypt(String texto, String chave) throws Exception{
        //Expandindo a Chave
        byte[] skBytes = getSecretKey(chave, 32);
        
        //Chama função de encriptação
        return DetEncrypt(texto, skBytes);
    }
    
    public static String DetEncrypt(String texto, byte[] skBytes) throws Exception{
        //Gerando chave a partir dos primeiros 16 bytes da chave expandida
        SecretKeySpec ctrKey = new SecretKeySpec(Arrays.copyOfRange(skBytes, 0, 16), "AES");
        
        //Gerando IV(HMAC) a partir dos últimos 16 bytes da chave expandida
        byte[] hmac = HmacSHA256(texto, Arrays.copyOfRange(skBytes, 16, 32));
        byte[] macBytes = Arrays.copyOf(hmac, 16);
        
        //Cifrando
        Cipher encripta = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encripta.init(Cipher.ENCRYPT_MODE, ctrKey, new IvParameterSpec(macBytes));
        byte[] encrypted =  encripta.doFinal(texto.getBytes("UTF-8"));
        
        //Gerando criptograma com hmac 
        return encryptedToString(macBytes, encrypted);
    }
    
    public static byte[][] StringToEncrypted(String crypto) throws Exception{
        //Extraindo macBytes e texto cifrado
        String[] c = crypto.split(";");
        String [] macKeyStr = c[0].split(" ");
        String [] cifraStr = c[1].split(" ");
        
        byte [] macBytes = new byte[macKeyStr.length];
        for (int i = 0; i < macKeyStr.length; i++)
            macBytes[i] = new Integer (macKeyStr[i]).byteValue();
        
        byte [] cifra = new byte[cifraStr.length];
        for (int i = 0; i < cifraStr.length; i++)
            cifra[i] = new Integer (cifraStr[i]).byteValue();
        
        byte[][] encrypted = {macBytes, cifra};
        return encrypted;
    }
    
    public static String DetDecrypt(String textocifrado, String chave) throws Exception{
        //Expandindo a Chave
        byte[] skBytes = getSecretKey(chave, 32);
        
        //Chamando função de decifração
        return DetDecrypt(textocifrado, skBytes);
    }
    
    public static String DetDecrypt(String textocifrado, byte[] skBytes) throws Exception{
        //Gerando chave
        SecretKeySpec ctrKey = new SecretKeySpec(Arrays.copyOfRange(skBytes, 0, 16), "AES");
        
        //Recuperando hmac e texto cifrado
        byte[][] encrypted = StringToEncrypted(textocifrado);
        byte[] macBytes = encrypted[0];
        byte[] cifra = encrypted[1];
        
        //Teste de autenticidade
//        String texto2 = "minha mensagem teste";
//        String textocifrado2 = DetEncrypt(texto2, chave);
//        byte[][]encrypted2 = StringToEncrypted(textocifrado2);
//        byte[] macBytes2 = encrypted2[0];
//        byte[] cifra2 = encrypted2[1];
//        Cipher decifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        decifra.init(Cipher.DECRYPT_MODE, ctrKey, new IvParameterSpec(macBytes2));
//        String decrypted = new String (decifra.doFinal(cifra2),"UTF-8");
//        System.out.println(decrypted);
        
        //Decifrando
        //byte[] decrypted = AES_SIV.decrypt(ctrKey.getEncoded(), macBytes, cifra);
        Cipher decifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decifra.init(Cipher.DECRYPT_MODE, ctrKey, new IvParameterSpec(macBytes));
        String decrypted = new String (decifra.doFinal(cifra),"UTF-8");
        
        //Verificando autenticidade
        byte[] hmac = HmacSHA256(decrypted, Arrays.copyOfRange(skBytes, 16, 32));
        hmac = Arrays.copyOf(hmac, 16);
        
        //Se mensagem não autêntica, retorna null
        int ok = 1;
        for (int i = 0; i < 16; i++)
            if (hmac[i] != macBytes[i])
                return null;
        
        return decrypted;
    }
}