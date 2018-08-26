/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.recipes.privacy;

import depspace.client.DepSpaceAdmin;
import depspace.extension.EDSExtensionRegistration;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eduardo
 */
public class SecureDistributedQueue {

    public SecureDistributedQueue() {
    }

    public void start(String[] args) {
        //int exec = 1;
        //int id = -1;
        //String create = "false";
        int id = Integer.parseInt(args[0]);
        String config = args[1];
        String ext_dir = args[2];

        int exec = Integer.parseInt(args[3]);

        boolean ext = Boolean.parseBoolean(args[4]);

        int num = Integer.parseInt(args[5]);

       

        if (!ext) {
            //System.out.println("entrou aqui");
            DSSecureDistributedQueue[] cl = new DSSecureDistributedQueue[num];
            for (int i = 0; i < num; i++) {
                cl[i] = new DSSecureDistributedQueue(id + i, exec);
            }

            
            for (int i = 0; i < num; i++) {
                cl[i].start();
            }
            
            for (int i = 0; i < num; i++) {
                try {
                    cl[i].join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(SecureDistributedQueue.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            System.out.println("Average - limit: "+cl[0].st.getAverage(true) / 1000 + " us ");
            System.out.println("DP - limit: "+cl[0].st.getDP(true) / 1000 + " us ");
        
            System.out.println("Average - all: "+cl[0].st.getAverage(false) / 1000 + " us ");
            System.out.println("DP - all: "+cl[0].st.getDP(false) / 1000 + " us ");
        } else {
            
             DepSpaceConfiguration.init(null);
             ExtSecureDistributedQueue[] cl = new ExtSecureDistributedQueue[num];
            
                        
             for (int i = 0; i < num; i++) {
                cl[i] = new ExtSecureDistributedQueue(id+i, ext_dir, exec);
                
            }

           
            
            for (int i = 0; i < num; i++) {
                cl[i].start();
            }
            
            for (int i = 0; i < num; i++) {
                try {
                    cl[i].join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(SecureDistributedQueue.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            System.out.println("Average - limit: "+cl[0].st.getAverage(true) / 1000 + " us ");
            System.out.println("DP - limit: "+cl[0].st.getDP(true) / 1000 + " us ");
        
            System.out.println("Average - all: "+cl[0].st.getAverage(false) / 1000 + " us ");
            System.out.println("DP - all: "+cl[0].st.getDP(false) / 1000 + " us ");
            
        }

    }

    public static void main(String[] args) {
        new SecureDistributedQueue().start(args);
        System.exit(0);
    }

}
