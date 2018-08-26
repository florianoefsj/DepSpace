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
public class DSSharedCounter extends Thread {

    private int executions;
    private boolean createSpace = true;
    private int id;

    public Storage st;

    /**
     * Creates a new instance of ClientTest
     *
     * @param clientId
     * @param exec
     */
    public DSSharedCounter(int clientId, int exec) {
        super("Client " + clientId);
        this.id = clientId;
        this.executions = exec;
        st = new Storage(executions);
        //this.createSpace = createSpace;
    }

    private void initCounter(DepSpaceAccessor accessor) {

        DepTuple tuple = DepTuple.createTuple(0);
        DepTuple template = DepTuple.createTuple(DepTuple.WILDCARD);

        try {
            DepTuple ret = accessor.cas(template, tuple);
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

                

                //System.out.println("ENVIAR RET");
                DepTuple ret = accessor.rdp(DepTuple.createTuple(DepTuple.WILDCARD));
                //System.out.println("PASSOU PELO RET");

                if (ret == null) {
                    System.out.println("ret é null");
                    return -1;
                }

                c = Double.parseDouble(ret.getFields()[0].toString());
                
                sucesso = accessor.replace(ret, DepTuple.createTuple(c + 1));

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

    @Override
    public void run() {

        try {
            String name = "DSCounter";

            DepSpaceConfiguration.init(null);

            Properties prop = DepSpaceProperties.createDefaultProperties(name);

            prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "false");

            // the DepSpace Accessor, who will access the DepSpace.
            DepSpaceAccessor accessor = null;
            if (this.createSpace) {
                accessor = new DepSpaceAdmin(this.id).createSpace(prop);
            } else {
                accessor = new DepSpaceAdmin(this.id).createAccessor(prop, createSpace);
            }

            System.out.println("Acessor pronto!");

            

            initCounter(accessor);
            
            
            Thread.currentThread().sleep(5000);

            execute(accessor);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
