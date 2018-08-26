package depspace.confidentiality;

import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * ProtectionVector. 
 *
 * @author		Alysson Bessani
 * @author2		Eduardo Alchieri
 * @author3		Rui Posse (ruiposse@gmail.com)
 * @version		DepSpace 2.0
 * @date		
 */
public class ProtectionVector implements Externalizable{
	
	// TODO comment
    public transient final static int PU = 0;
    public transient final static int CO = 1;
    public transient final static int PR = 2;
    
    
        //EDSON
    public transient final static int CD = 3;
    public transient final static int OR = 4;
    public transient final static int OP = 5;
    public transient final static int OR_ORE = 6;
    //CDKey: String (Qualquer tamanho) ou Bytes (32 Bytes Sha256 Key)
    //public transient byte[] CDKey = My32BytesKey;
    
    
    public transient String CDKey; 
    public transient String ORKey; 
    public transient String OR_OreKey;
    public transient PaillierPublicKey OPPublicKey;
    public transient PaillierPrivateKey OPPrivateKey;
        
    
    
    // TODO comment
    private int[] pTypes;
    
    // TODO comment
    public ProtectionVector(){}
    
    
    /**
     * Creates a new instance of ProtectionVector.
     * @param types TODO comment
     */
    public ProtectionVector(int[] types) {
        this.pTypes = types;
    }
    
    
    /**************************************************
	 *					 ACCESSORS					  *
	 **************************************************/
    public final int getLength() { return pTypes.length; }
    public final int getType(int i) { return pTypes[i]; }
    
    
    /**************************************************
     *				  Externalizable				  *
     **************************************************/
    
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    	int tam = in.readInt();
    	pTypes = new int[tam];
    	for(int i = 0; i < tam; i++){
    		pTypes[i] = in.readInt();
    	}
    }
    
    public void writeExternal(ObjectOutput out) throws IOException {
    	int tam = pTypes.length;
    	out.writeInt(tam);
    	for(int i = 0; i < tam; i++){
    		out.writeInt(pTypes[i]);
    	}
    }

}