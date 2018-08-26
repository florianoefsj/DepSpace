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
import depspace.server.DepSpaceListImpl;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class ExtSharedCounter extends Thread {

    private int executions = 0;
    private boolean createSpace = true;
    private int id;

  
    public Storage st;

    private String path;

    public ExtSharedCounter(int id, String basePath, int exec) {

        this.path = basePath;
        this.id = id;
        this.executions = exec;
        this.st = new Storage(exec);
    }

    public void initCounter(DepSpaceAccessor accessor) {


        DepTuple tuple = DepTuple.createTuple(DepSpaceListImpl.INCREMENT_OPERATION, 0);
        DepTuple template = DepTuple.createTuple(DepSpaceListImpl.INCREMENT_OPERATION, DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple);
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
        
        try {
            DepTuple ret = accessor.inp(DepTuple.createTuple(DepSpaceListImpl.INCREMENT_OPERATION, 1));
            if (ret == null) {
                System.out.println("ret é null");
                System.exit(0);
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

    @Override
    public void run() {

        try {

            String name = "ExtCounter";

           

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "false");

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

            
            //EDSExtensionRegistration.registerExtension(admin, CounterExtension.class, path);
            

            try {
                Thread.currentThread().sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(SecureSharedCounter.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            
            initCounter(accessor);

            execute(accessor);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
