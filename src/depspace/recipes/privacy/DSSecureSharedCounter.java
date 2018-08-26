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
import depspace.general.DepSpaceProperties;
import depspace.general.DepTuple;

import java.util.Properties;

/**
 *
 * @author eduardo
 */
public class DSSecureSharedCounter extends Thread {

    private int executions;
    private boolean createSpace = true;
    private int id;

    private String cdKey = "";

    public Storage st;

    /**
     * Creates a new instance of ClientTest
     *
     * @param clientId
     * @param exec
     */
    public DSSecureSharedCounter(int clientId, int exec) {
        super("Client " + clientId);
        this.id = clientId;
        this.executions = exec;
        st = new Storage(executions);
        //this.createSpace = createSpace;
    }

    private void initCounter(DepSpaceAccessor accessor) {

        int[] pvinfo = new int[1];
        pvinfo[0] = ProtectionVector.CD;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        pv1.CDKey = this.cdKey;

        ProtectionVector[] vectors = new ProtectionVector[2];
        vectors[0] = pv1;

        int[] pvinfo2 = new int[1];
        pvinfo2[0] = ProtectionVector.CD;
        ProtectionVector pv2 = new ProtectionVector(pvinfo2);
        pv2.CDKey = this.cdKey;
        vectors[1] = pv2;

        Context ctx = new Context(accessor.getTSName(), vectors);

        DepTuple tuple = DepTuple.createTuple(0);
        DepTuple template = DepTuple.createTuple(DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple, ctx);
            if (ret != null) {
                System.out.println("Contador já inicializado com: " + ret.getFields()[0]);
            } else {
                System.out.println("Inicializou o contador");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private double incrementAndGet(DepSpaceAccessor accessor) {

        double c = -1;
        DepTuple sucesso = null;
        do {
            /*if (c != -1) {
                System.out.println("TENTANDO NOVAMENTE");
            }*/

            try {

                int[] pvinfo = new int[1];
                pvinfo[0] = ProtectionVector.CD;
                ProtectionVector pv1 = new ProtectionVector(pvinfo);
                pv1.CDKey = this.cdKey;
                ProtectionVector[] vectors = new ProtectionVector[1];
                vectors[0] = pv1;

                Context ctx = new Context(accessor.getTSName(), vectors);

                //System.out.println("ENVIAR RET");
                DepTuple ret = accessor.rdp(DepTuple.createTuple(DepTuple.WILDCARD), ctx);
                //System.out.println("PASSOU PELO RET");

                if (ret == null) {
                    System.out.println("ret é null");
                    return -1;
                }

                c = Double.parseDouble(ret.getFields()[0].toString());
                //System.out.println("lido: " + c);
                pvinfo = new int[1];
                pvinfo[0] = ProtectionVector.CD;
                pv1 = new ProtectionVector(pvinfo);
                pv1.CDKey = this.cdKey;
                vectors = new ProtectionVector[2];
                vectors[0] = pv1;

                int[] pvinfo2 = new int[1];
                pvinfo2[0] = ProtectionVector.CD;
                ProtectionVector pv2 = new ProtectionVector(pvinfo2);
                pv2.CDKey = this.cdKey;
                vectors[1] = pv2;

                ctx = new Context(accessor.getTSName(), vectors);

                sucesso = accessor.replace(ret, DepTuple.createTuple(c + 1), ctx);

            } catch (Exception e) {
                e.printStackTrace();
                System.exit(0);
            }
        } while (sucesso == null);
        return c + 1;
    }

    public void execute(DepSpaceAccessor accessor) {
        for (int i = 0; i < executions; i++) {
            //System.out.println("Incrementando: " + incrementAndGet(accessor));

            long t1 = System.nanoTime();
            //System.out.println(incrementAndGet(accessor));
            incrementAndGet(accessor);
            st.store(System.nanoTime() - t1);
        }
    }

    public void shareKeys(DepSpaceAccessor accessor) {

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
            String name = "DSSecureCounter";

            DepSpaceConfiguration.init(null);

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");

            // the DepSpace Accessor, who will access the DepSpace.
            DepSpaceAccessor accessor = null;
            if (this.createSpace) {
                accessor = new DepSpaceAdmin(this.id).createSpace(prop);
            } else {
                accessor = new DepSpaceAdmin(this.id).createAccessor(prop, createSpace);
            }

            System.out.println("Acessor pronto!");

            shareKeys(accessor);

            initCounter(accessor);
            
            
            Thread.currentThread().sleep(5000);

            execute(accessor);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
