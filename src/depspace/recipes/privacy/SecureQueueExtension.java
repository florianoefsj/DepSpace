/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.recipes.privacy;

import depspace.extension.EDSBaseExtension;
import depspace.general.Context;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepTuple;
import java.util.Collection;

/**
 *
 * @author eduardo
 */
public class SecureQueueExtension extends EDSBaseExtension {

    //public static final String HEAD_ELEMENT = "head-element";
    private static final DepTuple QUEUE_TEMPLATE = DepTuple.createTuple("fila", DepTuple.WILDCARD, DepTuple.WILDCARD);

    // ################
    // # SUBSCRIPTION #
    // ################
    @Override
    public boolean matchesOperation(String tsName, DepSpaceOperation operation, Object arg) {
        if (operation == DepSpaceOperation.INP) {
            Object[] templateFields = ((DepTuple) arg).getFields();
            if (templateFields.length != 3) {
                return false;
            }
            return "fila".equals(templateFields[0]);
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
    private DepTuple getHeadElement() throws DepSpaceException {
        // Get queue elements
        Collection<DepTuple> tuples = extensionGate.rdAll(QUEUE_TEMPLATE);

        // Return if the queue is empty
        if (tuples.isEmpty()) {
            return null;
        }

        // Find the head element
        DepTuple head = null;
        long minTimestamp = Long.MAX_VALUE;
        int c = 0;
        for (DepTuple tuple : tuples) {
            long timestamp = (Long) tuple.getFields()[1];
            c++;
            if (minTimestamp <= timestamp) {
                continue;
            }
            minTimestamp = timestamp;
            head = tuple;
        }

        /*try {
            //parar c tempos de comparações
            Thread.currentThread().sleep(c * 0, 00011);
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }*/

        return head;
    }

    @Override
    protected DepTuple inp(DepTuple template, Context ctx) throws DepSpaceException {
        // Get head element
        DepTuple head = getHeadElement();

        // Return if the queue is empty
        if (head == null) {
            return null;
        }

        return extensionGate.inp(DepTuple.createTuple("fila", head.getFields()[1], DepTuple.WILDCARD));
    }

}
