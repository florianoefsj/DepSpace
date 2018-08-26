/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.confidentiality;


import java.math.BigInteger;
import jope.OPE;
import jope.ValueRange;

/**
 *
 * @author Edson Floriano
 */
public class OrderScheme {
    
    public static OPE OPE_init(){
        //Edson Floriano: Customizando intervalos
        ValueRange inRange = new ValueRange(new BigInteger("2").pow(32).negate(),
                        new BigInteger("2").pow(32));
        ValueRange outRange = new ValueRange(new BigInteger("2").pow(48).negate(),
                        new BigInteger("2").pow(48));
        
        //Edson Floriano: Exemplo de uso
        // inRange = new ValueRange(BigInteger.ZERO, new BigInteger("100"));
        // outRange = new ValueRange(BigInteger.ZERO, new BigInteger("200"));
        OPE o = new OPE(inRange, outRange);
        return o;
    }
    
//    public static BigInteger StringToBigInteger(String data){
//        OPE o = OPE_init();
//        BigInteger p = new BigInteger(data);
//        return p;
//    }
    
    public static BigInteger OPE_encrypt(String data, String key){
        OPE o = OPE_init();
        BigInteger p = new BigInteger("" + Integer.parseInt(data));
        return o.encrypt(p, key);
    }
    
    public static BigInteger OPE_decrypt(BigInteger cypher, String key){
        OPE o = OPE_init();
        return o.decrypt(cypher, key);
    }
    
    //Recebe query em claro e retorna query cifrada
    public static String OPE_query_detect(String query, String key){
        String [] q = query.split(";");
        String op = q[0];
        
        //Query simples op;n
        if (q.length == 2) 
            //Retornano op;e1
            return (op+";"+OPE_encrypt(q[1], key).toString());
        
        //Query de intervalo op;n1;n2
        if (q.length == 3)
            //Retornando op;e1;e2
            return (op+";"+OPE_encrypt(q[1], key).toString()
                    +";"+OPE_encrypt(q[2], key).toString());
        
        //Query inv√°lida ou consulta de igualdade
        return (OPE_encrypt(q[0], key).toString());
    }
    
    //Recebe query cifrada e executa consulta
    public static boolean OPE_query_run(String fp, String query){
        //Caso de igualdade
        if (fp.equals(query)) return true;
        
        //Caso query
        BigInteger e1 = new BigInteger(fp);
        
        String [] q = query.split(";");
        String op = q[0];
        
        
        //Caso query simples op;n
        if (q.length == 2) {
            BigInteger e2 = new BigInteger(q[1]);
            int res = e1.compareTo(e2);
            
            //Executando buscas
            if (op.equals("lt")) return (res < 0); 
            if (op.equals("le")) return (res <= 0); 
            if (op.equals("ge")) return (res >= 0);
            if (op.equals("gt")) return (res > 0);
        }
        
        //Caso query de intervalo op;n1;n2
        if (q.length == 3){
            BigInteger e2 = new BigInteger(q[1]);
            BigInteger e3 = new BigInteger(q[2]);
            
            //Executando buscas
            if (op.equals("cont")) return (new ValueRange(e2, e3)).contains(e1);
            if (op.equals("ncont")) return (!(new ValueRange(e2, e3)).contains(e1));
        }
        //Caso query inv·lida ou busca de igualdade
        boolean res = fp.equals(query);
        System.out.println(res);
        return res;
    }
}