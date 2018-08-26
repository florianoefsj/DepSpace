/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.confidentiality;

import java.security.SecureRandom;

/**
 *
 * @author Edson Floriano
 */
public class OREOrderScheme {

    static {
	         System.loadLibrary("oreblkc");
    }

    // args: 
    private native void blkOreC(String args[], int op);

    private byte[] ciphertext;
    private int res;
    
    public static String ORE_keygenerate (int size){
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[size];
        random.nextBytes(bytes);
        return ORE_ciphertext_to_string(bytes);
    }
    
    public static byte[] ORE_encrypt(String n1, String key){
        //Uso: enc (byte[]) secret_key (int/String) n
        String[] args = new String[3];
        args[0] = "enc";
        args[1] = key;
	args[2] = n1;

        OREOrderScheme blkorejni = new OREOrderScheme();
        blkorejni.blkOreC(args, 1);
        byte[] ciphertext1 = blkorejni.ciphertext;
        //System.out.println("ORE_encrypt: "+ORE_ciphertext_to_string(ciphertext1));
        return ciphertext1;
    }

    public static String ORE_ciphertext_to_string(byte[] ciphertext){

        String ctxt1_str = "";
        for (byte b: ciphertext){
                ctxt1_str = ctxt1_str + String.format("%02X", b);
        }
	return ctxt1_str;
    }

    public static byte[] ORE_string_to_ciphertext(String s) {
	int len = s.length();
    	byte[] data = new byte[len / 2];
    	for (int i = 0; i < len; i += 2) {
        	data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    	}
    	return data;
    }

    public static int ORE_compare(byte[] ciphertext1, byte[] ciphertext2){
        //cmp ctxt1 ctxt2
        OREOrderScheme blkorejni = new OREOrderScheme();

        String ctxt1_str = ORE_ciphertext_to_string(ciphertext1);
        String ctxt2_str = ORE_ciphertext_to_string(ciphertext2);

        String [] new_args = {"cmp", ctxt1_str, ctxt2_str};
        blkorejni.blkOreC(new_args, 2);

        /* -1: ciphertext1 < ciphertext2; 
            0: ciphertext1 = ciphertext2; 
            1: ciphertext1 > ciphertext2*/
        int res = blkorejni.res;
        //System.out.println("ORE_compare: "+res);
        return res;
    }
    
    public static String ORE_query_detect(String query, String key){
        String [] q = query.split(";");
        String op = q[0];
        
        //Query simples op;n
        //op: lt;le;eq;ge;gt
        if (q.length == 2) {
	    byte[] ciphertext1 = ORE_encrypt(q[1],key);    
	    String ctxt1_str = ORE_ciphertext_to_string(ciphertext1);

            return (op+";"+ctxt1_str);
        }
        
        //Caso nao seja uma query, apenas cifra o campo
	byte[] ciphertext1 = ORE_encrypt(q[0],key);    
	String ctxt1_str = ORE_ciphertext_to_string(ciphertext1);
        
        //System.out.println("ORE_query_detect: "+ctxt1_str);
        return (ctxt1_str);
    }
    
    //Recebe query cifrada e executa consulta
    public static boolean ORE_query_run(String fp, String query){
        
        byte[] e1 = ORE_string_to_ciphertext(fp);
        
        String [] q = query.split(";");
        int res;
            
        //Caso query simples op;n
        if (q.length == 2) {
            String op = q[0];
            byte[] e2 = ORE_string_to_ciphertext(q[1]);
            res = ORE_compare(e1,e2);
            
            //Executando buscas
            switch (op){
                case "lt": return (res < 0);
                case "le": return (res <= 0);
                case "ge": return (res >= 0);
                case "gt": return (res > 0);
                default: {
			System.out.println("Usage: <tuple_field> <[lt;|le;|ge;|gt;]template_field>");
			return false;}
            }
        }
        
        //Caso busca de igualdade
        
        else {
            byte[] e2 = ORE_string_to_ciphertext(q[0]);
            res = ORE_compare(e1,e2);
            //System.out.println("ORE_query_run: "+(res==0));
            //System.out.println("Query run: buscar igualdade: "+res);
            return (res == 0);
        }
        
    }
}
