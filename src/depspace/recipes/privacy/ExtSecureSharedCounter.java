/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.recipes.privacy;

import bftsmart.tom.util.Storage;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import depspace.client.DepSpaceAccessor;
import depspace.client.DepSpaceAdmin;
import depspace.confidentiality.OperableScheme;
import depspace.confidentiality.ProtectionVector;
import depspace.extension.EDSExtensionRegistration;
import depspace.general.Context;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceProperties;
import depspace.general.DepTuple;
import depspace.recipes.EDSSharedValueExtension;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class ExtSecureSharedCounter extends Thread {

    private int executions = 0;
    private boolean createSpace = true;
    private int id;

  

    private PaillierPrivateKey priv;
    private PaillierPublicKey pub;

    public Storage st;

    private String path;

    public ExtSecureSharedCounter(int id, String basePath, int exec) {

        this.path = basePath;
        this.id = id;
        this.executions = exec;
        this.st = new Storage(exec);
    }

    public void initCounter(DepSpaceAccessor accessor) {

        int[] pvinfo = new int[2];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.OP;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        pv1.OPPrivateKey = priv;
        pv1.OPPublicKey = pub;

        ProtectionVector[] vectors = new ProtectionVector[2];
        vectors[0] = pv1;

        int[] pvinfo2 = new int[2];
        pvinfo2[0] = ProtectionVector.PU;
        pvinfo2[1] = ProtectionVector.OP;
        ProtectionVector pv2 = new ProtectionVector(pvinfo2);
        pv2.OPPrivateKey = priv;
        pv2.OPPublicKey = pub;
        vectors[1] = pv2;

        Context ctx = new Context(accessor.getTSName(), vectors);

        DepTuple tuple = DepTuple.createTuple(SecureCounterExtension.INCREMENT_OPERATION, 0);
        DepTuple template = DepTuple.createTuple(SecureCounterExtension.INCREMENT_OPERATION, DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple, ctx);
            if (ret != null) {
                System.out.println("Contador já inicializado com: " + ret.getFields()[1]);
            } else {
                System.out.println("Inicializou o contador");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private double incrementAndGet(DepSpaceAccessor accessor) {
        int[] pvinfo = new int[2];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.OP;
        ProtectionVector pv1 = new ProtectionVector(pvinfo);
        pv1.OPPrivateKey = priv;
        pv1.OPPublicKey = pub;
        ProtectionVector[] vectors = new ProtectionVector[1];
        vectors[0] = pv1;
        Context ctx = new Context(accessor.getTSName(), vectors);
        try {
            DepTuple ret = accessor.inp(DepTuple.createTuple(SecureCounterExtension.INCREMENT_OPERATION, 1), ctx);
            if (ret == null) {
                System.out.println("ret é null");
            }

            return Double.parseDouble(ret.getFields()[1].toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }

    public void execute(DepSpaceAccessor accessor) {
        for (int i = 0; i < executions; i++) {
            long t1 = System.nanoTime();
            //System.out.println(incrementAndGet(accessor));
            incrementAndGet(accessor);
            st.store(System.nanoTime() - t1);
        }
    }

    public void shareKeys(DepSpaceAccessor accessor) {

        priv = OperableScheme.generatePrivateKey(512);
        pub = OperableScheme.generatePublicKey(priv);

        int[] pvinfo = new int[3];
        pvinfo[0] = ProtectionVector.PU;
        pvinfo[1] = ProtectionVector.PU;
        pvinfo[2] = ProtectionVector.PR;

        ProtectionVector pv1 = new ProtectionVector(pvinfo);

        ProtectionVector[] vectors = new ProtectionVector[2];
        vectors[0] = pv1;

        int[] pvinfo2 = new int[3];
        pvinfo2[0] = ProtectionVector.PU;
        pvinfo2[1] = ProtectionVector.PU;
        pvinfo2[2] = ProtectionVector.PR;

        ProtectionVector pv2 = new ProtectionVector(pvinfo2);
        vectors[1] = pv2;

        Context ctx = new Context(accessor.getTSName(), vectors);

        DepTuple tuple = DepTuple.createTuple("keys", OperableScheme.publicKeyToString(pub), OperableScheme.privateKeyToString(priv));
        DepTuple template = DepTuple.createTuple("keys", DepTuple.WILDCARD, DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple, ctx);
            if (ret != null) {
                pub = OperableScheme.stringToPublicKey((String) ret.getFields()[1]);
                priv = OperableScheme.stringToPrivateKey((String) ret.getFields()[2]);

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

            String name = "ExtSecureCounter";

           

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");

            // the DepSpace Accessor, who will access the DepSpace.
            DepSpaceAccessor accessor = null;
            //System.out.println("Vai criar ADM "+id);
            DepSpaceAdmin admin = new DepSpaceAdmin(this.id);
            //System.out.println("CRIOU ADM "+id);
            if (this.createSpace) {
                accessor = admin.createSpace(prop);
            } else {
                accessor = admin.createAccessor(prop, createSpace);
            }

            System.out.println("Acessor pronto! "+id);

            
            EDSExtensionRegistration.registerExtension(admin, SecureCounterExtension.class, path);
            

            try {
                Thread.currentThread().sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(SecureSharedCounter.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            
            shareKeys(accessor);

            initCounter(accessor);

            execute(accessor);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
