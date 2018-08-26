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
import depspace.extension.EDSExtensionRegistration;
import depspace.general.Context;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceProperties;
import depspace.general.DepTuple;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class ExtSecureDistributedQueue extends Thread {

    private int executions = 0;
    private boolean createSpace = true;
    private int id;

    public Storage st;

    private String path;

    private DepSpaceAccessor accessor;

    public ExtSecureDistributedQueue(int id, String basePath, int exec) {

        this.path = basePath;
        this.id = id;
        this.executions = exec;
        this.st = new Storage(exec);
    }

    public void add(byte[] data) {
        int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.PU;
        pvinfo[2] = ProtectionVector.PR;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);

        try {

            try {
                //parar dois tempos de cifrar: um para o template e outro para testar a tupla recebida
                Thread.currentThread().sleep(0,01022);
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }

            accessor.out(DepTuple.createTuple("fila", System.currentTimeMillis(), data), ctx);
        } catch (DepSpaceException ex) {
            ex.printStackTrace();
        }
    }

    public byte[] take() throws DepSpaceException, InterruptedException {
        int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.PU;
        pvinfo[2] = ProtectionVector.PR;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);

        try {
            //parar dois tempos de cifrar: um para o template e outro para testar a tupla recebida (faltou a comparacao)
            Thread.currentThread().sleep(0,01022);
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }
        DepTuple head = accessor.inp(DepTuple.createTuple("fila", DepTuple.WILDCARD, DepTuple.WILDCARD), ctx);
        if (head == null) {
            return null;
        }
        //System.out.println("id "+head.getFields()[1]);
        return (byte[]) head.getFields()[2];
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

    }

    @Override
    public void run() {

        try {

            String name = "ExtSecureQueue";

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");

            // the DepSpace Accessor, who will access the DepSpace.
            //System.out.println("Vai criar ADM "+id);
            DepSpaceAdmin admin = new DepSpaceAdmin(this.id);
            //System.out.println("CRIOU ADM "+id);
            if (this.createSpace) {
                accessor = admin.createSpace(prop);
            } else {
                accessor = admin.createAccessor(prop, createSpace);
            }

            System.out.println("Acessor pronto! " + id);

            //EDSExtensionRegistration.registerExtension(admin, QueueExtension.class, path);

            try {
                Thread.currentThread().sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(SecureSharedCounter.class.getName()).log(Level.SEVERE, null, ex);
            }

            shareKeys();

            execute();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
