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
public class CounterExtension extends EDSBaseExtension {

    public static final String INCREMENT_OPERATION = "increment";

    private static final DepTuple TEMPLATE = DepTuple.createTuple(INCREMENT_OPERATION, DepTuple.WILDCARD);

   

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
        }
        int counterValue = (Integer) tuple.getFields()[1];
        extensionGate.out(DepTuple.createTuple(INCREMENT_OPERATION,counterValue + 1));
        return tuple;
    }

}
