/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.confidentiality;


import depspace.general.Context;
import depspace.general.DepSpaceException;

import depspace.general.DepTuple;

import depspace.server.DepSpaceListImpl;
import java.util.ArrayList;
import java.util.Collection;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class DepSpaceConfidentialityImpl extends DepSpaceListImpl {

    protected List<ProtectionVector> protVector = new LinkedList<ProtectionVector>();

    private static final DepTuple QUEUE_TEMPLATE = DepTuple.createTuple("fila", DepTuple.WILDCARD, DepTuple.WILDCARD);
    
    public DepSpaceConfidentialityImpl(boolean realTimeRenew) {
        super(realTimeRenew);
        System.out.println("CRIOU UMA CONF LAYER");
    }

    public void clean(DepTuple tuple, Context ctx) {
        for (int i = 0; i < tuplesBag.size(); i++) {
            DepTuple match = tuplesBag.get(i);
            if (match.getPublishedShares().hashCode()
                    == tuple.getPublishedShares().hashCode()) {
                tuplesBag.remove(i);
                protVector.remove(i);
                break;
            }
        }
    }

    public DepTuple cas(DepTuple template, DepTuple tuple, Context ctx) {
        DepTuple result = rdp(template, ctx);

        if (result == null) {
            super.out(tuple, ctx);

            //System.out.println(tuple);
            protVector.add(ctx.protectionVectors[1]);
        }

        return result;
    }


    
    public void out(DepTuple tuple, Context ctx) {
        super.out(tuple, ctx);
        computeStatistics();
        protVector.add(ctx.protectionVectors[0]);
    }

    public DepTuple rdp(DepTuple template, Context ctx) {
        computeStatistics();
        DepTuple dt = findMatching(template, false, ctx);
        // System.out.println("Tupla lida: "+dt);
        return dt;
    }

    public DepTuple inp(DepTuple template, Context ctx) {
        computeStatistics();
       
        DepTuple ret = findMatching(template, true, ctx);
        
        //System.out.println(template+" INP: "+ret);
        return ret;
    }

    
    // #############
    // # EXECUTION #
    // #############
    private DepTuple getHeadElement(Context ctx) throws DepSpaceException {
        // Get queue elements
        Collection<DepTuple> tuples = rdAll(QUEUE_TEMPLATE,ctx);

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

        try {
            //parar c tempos de comparações
            Thread.currentThread().sleep(c * 0,00011);
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }

        return head;
    }

    
    public DepTuple inp_fila(DepTuple template, Context ctx)  {
        try {
            // Get head element
            DepTuple head = getHeadElement(ctx);
             computeStatistics();
            // Return if the queue is empty
            if (head == null) {
                return null;
            }
            
            return inp(DepTuple.createTuple("fila", head.getFields()[1], DepTuple.WILDCARD),ctx);
        } catch (DepSpaceException ex) {
           ex.printStackTrace();
           return null;
        }
    }

    
    @Override
    public Collection<DepTuple> rdAll(DepTuple template, Context ctx) {
        ArrayList<DepTuple> result = new ArrayList<DepTuple>();
        int tuplesToRead = (template.getN_Matches() > 0) ? template.getN_Matches() : tuplesBag.size();
        for (int i = 0; i < tuplesBag.size() && (tuplesToRead > 0); i++) {
            DepTuple tuple = tuplesBag.get(i);
            ProtectionVector pv = protVector.get(i);
            if (tuple.canRd(ctx.invokerID) && match(tuple, template, pv, ctx.protectionVectors[0])) {
                result.add(tuple);
                tuplesToRead--;
            }
        }
        return result;
    }


    public DepTuple findMatching(DepTuple template, boolean remove, Context ctx) {
        if (template != null) {
            try {
                int invokerId = ctx.invokerID;
                for (int i = 0; i < tuplesBag.size(); i++) {
                    DepTuple tuple = tuplesBag.get(i);
                    ProtectionVector pv = protVector.get(i);
                    boolean haveAccess = remove ? tuple.canIn(invokerId) : tuple.canRd(invokerId);
                    if (haveAccess && match(tuple, template, pv, ctx.protectionVectors[0])) {
                        if (remove) {
                            tuplesBag.remove(i);
                            protVector.remove(i);

                        }
                        return tuple;
                    }
                }
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private boolean match(DepTuple tuple, DepTuple template,
            ProtectionVector tuPv, ProtectionVector tePv) {
        if (tuPv == tePv) {
            return matchFinal(tuple, template, tePv);
        } else if (tuPv == null || tePv == null) {
            return false;
        } else if (tuPv.getLength() != tePv.getLength()) {
            return false;
        }
        for (int i = 0; i < tuPv.getLength(); i++) {
            if (tuPv.getType(i) != tePv.getType(i)) {
                return false;
            }
        }
        return matchFinal(tuple, template, tePv);
    }

    protected boolean matchFinal(DepTuple tuple, DepTuple template, ProtectionVector pv) {
        Object[] tupleFields = tuple.getFields();
        Object[] templateFields = template.getFields();

        int n = tupleFields.length;

        if (n != templateFields.length) {
            return false;
        }
        
                
        for (int i = 0; i < n; i++) {
            if (!templateFields[i].equals(DepTuple.WILDCARD)) {
                //EDSON
                //System.out.println("tuple field: "+tupleFields[i].toString());
                //System.out.println("template field: "+templateFields[i].toString());
                
                if (pv != null && pv.getType(i) == ProtectionVector.OR){
                    return (OrderScheme.OPE_query_run(tupleFields[i].toString(), templateFields[i].toString()));
                }if (pv != null && pv.getType(i) == ProtectionVector.OR_ORE){
                    return(OREOrderScheme.ORE_query_run(tupleFields[i].toString(), templateFields[i].toString())); 
                } else if (!templateFields[i].equals(tupleFields[i])) {
                    return false;
                }
            }
        }
        return true;
    }

}
