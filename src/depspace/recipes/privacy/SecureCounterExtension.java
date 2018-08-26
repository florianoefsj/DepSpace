/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.recipes.privacy;


import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import depspace.confidentiality.OperableScheme;
import depspace.extension.EDSBaseExtension;
import depspace.general.Context;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepTuple;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class SecureCounterExtension extends EDSBaseExtension {

    public static final String INCREMENT_OPERATION = "increment";

    private static final DepTuple TEMPLATE = DepTuple.createTuple(INCREMENT_OPERATION, DepTuple.WILDCARD);

    private PaillierPublicKey pk = null;
    
   

    // ################
    // # SUBSCRIPTION #
    // ################
    @Override
    public boolean matchesOperation(String tsName, DepSpaceOperation operation, Object arg) {
    
        if (operation == DepSpaceOperation.INP) {
            Object[] templateFields = ((DepTuple) arg).getFields();
            if (templateFields.length != 2) {
                return false;
            }
            return INCREMENT_OPERATION.equals(templateFields[0]);
        } else if (operation == DepSpaceOperation.CAS) {
            return true;
        }
        return false;
    }

    @Override
    public boolean matchesEvent(String tsName, DepSpaceOperation operation, DepTuple tuple) {
        return false;
    }

    // #############
    // # EXECUTION #
    // #############
    @Override
    protected DepTuple inp(DepTuple template, Context ctx) throws DepSpaceException {
        // Get and increment
        DepTuple tuple = extensionGate.inp(TEMPLATE);
           if (tuple == null) {
            extensionGate.error("There is no shared-counter tuple to increment");
            return null;
        } else {
                EncryptedNumber en1 = OperableScheme.StringToEncrypted(tuple.getFields()[1].toString(), pk);
                EncryptedNumber en2 = OperableScheme.StringToEncrypted(template.getFields()[1].toString(), pk);
                EncryptedNumber result = OperableScheme.add(en1, en2);

                tuple.getFields()[1] = OperableScheme.encryptedToString(result);
                tuple.modified();
                
                extensionGate.out(tuple);
                
                return tuple;
        }

    }

    @Override
    public DepTuple cas(DepTuple template, DepTuple tuple, Context ctx) throws DepSpaceException {
        DepTuple r = extensionGate.cas(template, tuple);
        if (r == null && this.pk == null) {
            if (tuple.getFields() != null && tuple.getFields().length == 3 && tuple.getFields()[0].equals("keys")) {
                this.pk = OperableScheme.stringToPublicKey((String) tuple.getFields()[1]);
            }
        }else if (pk == null){
            if (r.getFields() != null && r.getFields().length == 3 && r.getFields()[0].equals("keys")) {
                this.pk = OperableScheme.stringToPublicKey((String) r.getFields()[1]);
            }
        }
        return r;
    }
}