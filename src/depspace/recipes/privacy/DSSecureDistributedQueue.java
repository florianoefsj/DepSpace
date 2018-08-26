/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.recipes.privacy;

import bftsmart.tom.util.Storage;
import depspace.client.DepSpaceAccessor;
import depspace.client.DepSpaceAdmin;
import depspace.confidentiality.ProtectionVector;
import depspace.general.Context;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceProperties;
import depspace.general.DepTuple;
import depspace.recipes.DepSpaceQueue;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class DSSecureDistributedQueue extends Thread {

    private int executions;
    private boolean createSpace = true;
    private int id;
    private DepSpaceAccessor accessor;

    public Storage st;

    private final DepSpaceQueueSorter sorter;

    private final long takeRetryTimeout = 1;

    private String cdKey = "";

    /**
     * Creates a new instance of ClientTest
     *
     * @param clientId
     * @param exec
     */
    public DSSecureDistributedQueue(int clientId, int exec) {
        super("Client " + clientId);
        this.id = clientId;
        this.executions = exec;
        st = new Storage(executions);
        //this.createSpace = createSpace;
        this.sorter = new DepSpaceQueueSorter();
    }

    private static class DepSpaceQueueSorter implements Comparator<DepTuple> {

        @Override
        public int compare(DepTuple tupleA, DepTuple tupleB) {
            return ((Long) tupleA.getFields()[1]).compareTo((Long) tupleB.getFields()[1]);
        }

    }

    public void add(byte[] data) {
        int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.CD;
        pvinfo[2] = ProtectionVector.PR;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        pv1.CDKey = this.cdKey;
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);
       
        
        try {
            accessor.out(DepTuple.createTuple("fila", System.currentTimeMillis(), data), ctx);
        } catch (DepSpaceException ex) {
            ex.printStackTrace();
        }
    }

    private List<DepTuple> getOrderedElements() throws DepSpaceException {
        /*int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.PR;
        pvinfo[2] = ProtectionVector.PR;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);

        List<DepTuple> sortedQueue = new LinkedList<DepTuple>(
                accessor.rdAll(DepTuple.createTuple("fila", DepTuple.WILDCARD, DepTuple.WILDCARD), ctx));
        
        
        
        Collections.sort(sortedQueue, sorter);
        return sortedQueue;*/
        List<DepTuple> sortedQueue = new LinkedList<DepTuple>();
        DepTuple lido = null;

        int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.CD;
        pvinfo[2] = ProtectionVector.PR;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        pv1.CDKey = this.cdKey;
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);
        lido = accessor.rdp(DepTuple.createTuple("fila", DepTuple.WILDCARD, DepTuple.WILDCARD), ctx);
        if (lido != null) {
            sortedQueue.add(lido);
        }

        Collections.sort(sortedQueue, sorter);
        return sortedQueue;

    }

    private byte[] remove() {

        DepTuple head = null;
        while (true) {
            try {
                // Get sorted queue
                List<DepTuple> sortedQueue = getOrderedElements();
                // Return if the queue is empty
                if (sortedQueue.isEmpty()) {
                    return null;
                }
                // Remove head element from the queue, possibly retry
                for (DepTuple element : sortedQueue) {
                    int[] pvinfo = new int[3];
                    pvinfo[0] = ProtectionVector.PU;
                    pvinfo[1] = ProtectionVector.CD;
                    pvinfo[2] = ProtectionVector.PR;
                    ProtectionVector pv1 = new ProtectionVector(pvinfo);
                    pv1.CDKey = this.cdKey;
                    ProtectionVector[] vectors = new ProtectionVector[1];
                    vectors[0] = pv1;
                    Context ctx = new Context(accessor.getTSName(), vectors);

                    head = accessor.inp(DepTuple.createTuple("fila", element.getFields()[1], DepTuple.WILDCARD), ctx);

                    if (head != null) {
                        //System.out.println(head.getFields()[1] + " encontrou :" + element.getFields()[1]);
                        return (byte[]) head.getFields()[2];
                    }
                }
            } catch (DepSpaceException ex) {
                ex.printStackTrace();
            }
        }
    }

    public byte[] take() throws DepSpaceException, InterruptedException {
        byte[] head;
        while ((head = remove()) == null) {
            Thread.sleep(takeRetryTimeout);
        }
        return head;
    }

    public void execute() {
        for (int i = 0; i < executions; i++) {
            try {
                //System.out.println("Incrementando: " + incrementAndGet(accessor));

                long t1 = System.nanoTime();
                //System.out.println();
                byte[] value = new byte[0];

                // System.out.println("vai adicionar");
                add(value);

               
                //System.out.println("Adicionou");
                take();

                //System.out.println("Leu");
                st.store(System.nanoTime() - t1);
            } catch (DepSpaceException ex) {
                ex.printStackTrace();
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }
    }

    public void shareKeys() {

        this.cdKey = "minha chave!";
        int[] pvinfo = new int[2];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.PR;

        ProtectionVector pv1 = new ProtectionVector(pvinfo);

        ProtectionVector[] vectors = new ProtectionVector[2];
        vectors[0] = pv1;

        int[] pvinfo2 = new int[2];
        pvinfo2[0] = ProtectionVector.PU;
        pvinfo2[1] = ProtectionVector.PR;

        ProtectionVector pv2 = new ProtectionVector(pvinfo2);
        vectors[1] = pv2;

        Context ctx = new Context(accessor.getTSName(), vectors);

        DepTuple tuple = DepTuple.createTuple("key", this.cdKey);
        DepTuple template = DepTuple.createTuple("key", DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple, ctx);
            if (ret != null) {
                this.cdKey = ((String) ret.getFields()[1]);

                System.out.println("USANDO CHAVES DO ESPAÇO");
            } else {
                System.out.println("USANDO SUAS PRóPRIAS CHAVES");
            }

            //System.out.println("chave pub: " + pub.toString());
            //System.out.println("chave priv: " + priv.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {

        try {
            String name = "DSSecureQueue";

            DepSpaceConfiguration.init(null);

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");

            // the DepSpace Accessor, who will access the DepSpace.
            if (this.createSpace) {
                accessor = new DepSpaceAdmin(this.id).createSpace(prop);
            } else {
                accessor = new DepSpaceAdmin(this.id).createAccessor(prop, createSpace);
            }

            System.out.println("Acessor pronto!");

            shareKeys();
            
            execute();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
