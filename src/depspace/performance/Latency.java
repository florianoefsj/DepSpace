/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.performance;


import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import depspace.client.DepSpaceAccessor;
import depspace.client.DepSpaceAdmin;
import depspace.confidentiality.ConfidentialityScheme;
import depspace.confidentiality.DeterministicScheme;
import depspace.confidentiality.OperableScheme;
import depspace.confidentiality.OREOrderScheme;
import depspace.confidentiality.OrderScheme;
import depspace.confidentiality.ProtectionVector;
import depspace.general.Context;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepSpaceProperties;
import depspace.general.DepTuple;
import depspace.util.Storage;
import java.io.IOException;
import java.util.Properties;
import pvss.InvalidVSSScheme;
import pvss.PVSSEngine;
import pvss.PublicInfo;
import pvss.PublishedShares;
import pvss.Share;

/**
 *
 * @author eduardo
 */
public class Latency {

    public static int initId = 0;

    public static String tsName = "Latency";

    //public static int op =
    //public static boolean stop = false;
    @SuppressWarnings("static-access")
    public static void main(String[] args) throws IOException {
        if (args.length < 6) {
            System.out.println("Usage: ... PerformanceTest <num. clients> <process id> <number of operations> <operation> <field type> <size>");
            System.exit(-1);
        }

        int numThreads = Integer.parseInt(args[0]);
        initId = Integer.parseInt(args[1]);

        int numberOfOps = Integer.parseInt(args[2]);
        //int requestSize = Integer.parseInt(args[3]);
        DepSpaceOperation opType = DepSpaceOperation.OUT;

        if (args[3].equalsIgnoreCase("inp")) {
            opType = DepSpaceOperation.INP;
        } else if (args[3].equalsIgnoreCase("rdp")) {
            opType = DepSpaceOperation.RDP;
        }

        int fieldsType = ProtectionVector.PU;
        if (args[4].equalsIgnoreCase("pr")) {
            fieldsType = ProtectionVector.PR;
        } else if (args[4].equalsIgnoreCase("co")) {
            fieldsType = ProtectionVector.CO;

        } else if (args[4].equalsIgnoreCase("cd")) {
            fieldsType = ProtectionVector.CD;

        } else if (args[4].equalsIgnoreCase("op")) {
            fieldsType = ProtectionVector.OP;

        } else if (args[4].equalsIgnoreCase("or")) {
            fieldsType = ProtectionVector.OR;

        } else if (args[4].equalsIgnoreCase("or_ore")) {
            fieldsType = ProtectionVector.OR_ORE;
        }

        int size = Integer.parseInt(args[5]);

        new Latency.Client(initId, numberOfOps, opType, fieldsType, size).run();

    }

    /*  public static void stop() {
        stop = true;
    }

    public static void change() {
        if (op == BFTList.CONTAINS) {
            op = BFTList.ADD;
        } else {
            op = BFTList.CONTAINS;
        }
    }
     */
    static class Client {

        int id;
        int numberOfOps;
        DepSpaceOperation opType;
        int size = 3;
        int fieldsTyple = 0;

        private PaillierPrivateKey priv;
        private PaillierPublicKey pub;

        private String cdKey;
        private String orKey;
        private String or_OreKey;
        
        protected PVSSEngine engine;
    

        public Client(int id, int numberOfOps, DepSpaceOperation op, int fieldsType, int size) {
            //super("Client " + id);
            this.size = size;
            this.id = id;
            this.numberOfOps = numberOfOps;
            this.opType = op;

            this.fieldsTyple = fieldsType;

        }

        private final Context getContext(DepSpaceAccessor accessor) {

            ProtectionVector[] vectors = new ProtectionVector[1];

            int[] types = new int[this.size];
            for (int i = 0; i < this.size; i++) {

                types[i] = this.fieldsTyple;

            }
            vectors[0] = new ProtectionVector(types);

            vectors[0].OPPrivateKey = this.priv;
            vectors[0].OPPublicKey = this.pub;
            vectors[0].CDKey = this.cdKey;
            vectors[0].ORKey = this.orKey;
            vectors[0].OR_OreKey = this.or_OreKey;
            return new Context(accessor.getTSName(), vectors);
        }

        private void shareOPKeys(DepSpaceAccessor accessor) {
            priv = OperableScheme.generatePrivateKey(3072);
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

            DepTuple tuple = DepTuple.createTuple("OPkeys", OperableScheme.publicKeyToString(pub), OperableScheme.privateKeyToString(priv));
            DepTuple template = DepTuple.createTuple("OPkeys", DepTuple.WILDCARD, DepTuple.WILDCARD);

            try {
                DepTuple ret = accessor.cas(template, tuple, ctx);
                if (ret != null) {
                    pub = OperableScheme.stringToPublicKey((String) ret.getFields()[1]);
                    priv = OperableScheme.stringToPrivateKey((String) ret.getFields()[2]);

                    System.out.println("USANDO CHAVES DO ESPAÇO");
                } else {
                    System.out.println("USANDO SUAS PRÓPRIAS CHAVES");
                }

                //System.out.println("chave pub: " + pub.toString());
                //System.out.println("chave priv: " + priv.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        
        private void shareCDKeys(DepSpaceAccessor accessor) {
            //Gerando chave de 32 bytes (256 bits)
            cdKey = DeterministicScheme.Det_keygenerate(32);
            
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

            DepTuple tuple = DepTuple.createTuple("CDkey", cdKey);
            DepTuple template = DepTuple.createTuple("CDkey", DepTuple.WILDCARD);

            try {
                DepTuple ret = accessor.cas(template, tuple, ctx);
                if (ret != null) {
                    //pub = OperableScheme.stringToPublicKey((String) ret.getFields()[1]);
                    //priv = OperableScheme.stringToPrivateKey((String) ret.getFields()[2]);
                    cdKey = (String) ret.getFields()[1];

                    System.out.println("USANDO CHAVES DO ESPAÇO");
                } else {
                    System.out.println("USANDO SUAS PRÓPRIAS CHAVES");
                }

                //System.out.println("chave pub: " + pub.toString());
                //System.out.println("chave priv: " + priv.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        
        private void shareORKeys(DepSpaceAccessor accessor) {
            //Gerando chave de 16 bytes (128 bits)
            orKey = DeterministicScheme.Det_keygenerate(16);

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

            DepTuple tuple = DepTuple.createTuple("ORkey", orKey);
            DepTuple template = DepTuple.createTuple("ORkey", DepTuple.WILDCARD);

            try {
                DepTuple ret = accessor.cas(template, tuple, ctx);
                if (ret != null) {
                    //pub = OperableScheme.stringToPublicKey((String) ret.getFields()[1]);
                    //priv = OperableScheme.stringToPrivateKey((String) ret.getFields()[2]);
                    orKey = (String) ret.getFields()[1];

                    System.out.println("USANDO CHAVES DO ESPAÇO");
                } else {
                    System.out.println("USANDO SUAS PRÓPRIAS CHAVES");
                }

                //System.out.println("chave pub: " + pub.toString());
                //System.out.println("chave priv: " + priv.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        private void shareOR_OREKeys(DepSpaceAccessor accessor) {
            //Gerando chave de 16 bytes (128 bits)
            //or_OreKey = OREOrderScheme.ORE_keygenerate(16);
            //Gerando chave de 32 bytes (256 bits)
            or_OreKey = OREOrderScheme.ORE_keygenerate(32);

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

            DepTuple tuple = DepTuple.createTuple("OR_OREkey", or_OreKey);
            DepTuple template = DepTuple.createTuple("OR_OREkey", DepTuple.WILDCARD);

            try {
                DepTuple ret = accessor.cas(template, tuple, ctx);
                if (ret != null) {
                    //pub = OperableScheme.stringToPublicKey((String) ret.getFields()[1]);
                    //priv = OperableScheme.stringToPrivateKey((String) ret.getFields()[2]);
                    or_OreKey = (String) ret.getFields()[1];

                    System.out.println("USANDO CHAVES DO ESPAÇO");
                } else {
                    System.out.println("USANDO SUAS PRÓPRIAS CHAVES");
                }

                //System.out.println("chave pub: " + pub.toString());
                //System.out.println("chave priv: " + priv.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        private DepSpaceAccessor configure() {
            

                try {

                    DepSpaceConfiguration.init(null);

                    Properties prop = DepSpaceProperties.createDefaultProperties(tsName);

                    prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");

                    // the DepSpace Accessor, who will access the DepSpace.
                    DepSpaceAccessor accessor = null;

                    accessor = new DepSpaceAdmin(this.id).createSpace(prop);

                    System.out.println("Acessor pronto!");

                    Thread.currentThread().sleep(5000);

                    if (this.fieldsTyple == ProtectionVector.CD) {
                        shareCDKeys(accessor);
                    } else if (this.fieldsTyple == ProtectionVector.OP) {
                        shareOPKeys(accessor);
                    } else if (this.fieldsTyple == ProtectionVector.OR) {
                        shareORKeys(accessor);
                    }else if (this.fieldsTyple == ProtectionVector.OR_ORE) {
                        shareOR_OREKeys(accessor);
                    }

                    if (opType == DepSpaceOperation.INP) {
                        initINPExp(accessor);
                    } else if (opType == DepSpaceOperation.RDP) {
                        initRDPExp(accessor);
                    }

                    return accessor;
                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                }

         
        }

        

        private void initINPExp(DepSpaceAccessor a) {
            //for (int i = 0; i <= this.numberOfOps; i++) {
            for (int i = 0; i <= 50; i++) {
                try {
                    a.out(get(0), getContext(a));

                } catch (DepSpaceException ex) {
                    ex.printStackTrace();
                }
            }
        }

        private void initRDPExp(DepSpaceAccessor a) {

            try {
                a.out(get(0), getContext(a));
            } catch (DepSpaceException ex) {
                ex.printStackTrace();
            }
        }

        public DepTuple get(int i) {
            if (size == 3) {
                return DepTuple.createTuple(i, i, i);
            } else if (size == 5) {
                return DepTuple.createTuple(i, i, i, i, i);

            } else {
                return DepTuple.createTuple(i, i, i, i, i, i, i);
            }
        }

        //@Override
        public void run() {

            DepSpaceAccessor a = configure();

            Storage st = new Storage(numberOfOps);

            System.out.println("Executing experiment for " + numberOfOps + " ops");

            Object[] fields = new Object[this.size];
            for (int i = 0; i < this.size; i++) {
                //fields[i] = "*";
                fields[i] = 0;
            }

            if (this.fieldsTyple != ProtectionVector.PR && this.fieldsTyple != ProtectionVector.OP) {
                fields[0] = 0;

            }
            String fingerprint;
            DepTuple template = DepTuple.createTuple(fields);
            DepTuple[] res = new DepTuple[numberOfOps];
            
            try {
                for (int i = 0; i < numberOfOps; i++) {
                    
                    /* try {
                        Thread.sleep(100);
                        //Thread.sleep(50);
                    } catch (InterruptedException ex) {
                        ex.printStackTrace();
                    }*/
                    if (i % 50 == 0) {
                        System.out.println("Sending " + i);
                    }

                    if (opType == DepSpaceOperation.OUT) {

                        //long last_send_instant = System.nanoTime();

                        //a.out(get(0), getContext(a));
                        switch (this.fieldsTyple){
                            case (ProtectionVector.CO):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = engine.hash(engine.getPublicInfo(),
                                fields[0].toString().getBytes()).toString();
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.CD):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = DeterministicScheme.HmacSHA256Str(
                                    fields[0].toString(), this.cdKey);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OP):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = OperableScheme.encryptedToString(
                                OperableScheme.encrypt(this.pub, fields[0].toString()));
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OR):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = OrderScheme.OPE_query_detect(fields[0].toString(), this.orKey);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OR_ORE):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = OREOrderScheme.ORE_query_detect(fields[0].toString(),this.or_OreKey);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            default:{
                                break;
                            }
                        }
                        
                       // System.out.println("Terminou o OUT");
                        //st.store(System.nanoTime() - last_send_instant);
                    } else if (opType == DepSpaceOperation.RDP) {
                        
                        //long last_send_instant = System.nanoTime();
                        //res[i] = a.rdp(template, getContext(a));
                        //st.store(System.nanoTime() - last_send_instant);
                        
                        switch (this.fieldsTyple){
                            case (ProtectionVector.CO):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = engine.hash(engine.getPublicInfo(), 
                                        fields[0].toString().getBytes()).toString();
                                fingerprint.equals(fingerprint);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.CD):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = DeterministicScheme.HmacSHA256Str(
                                    fields[0].toString(), this.cdKey);
                                fingerprint.equals(fingerprint);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OP):{
                                fingerprint = OperableScheme.encryptedToString(
                                OperableScheme.encrypt(this.pub, fields[0].toString()));
                                long last_send_instant = System.nanoTime();
                                OperableScheme.decrypt(this.priv, OperableScheme.StringToEncrypted(fingerprint, this.pub));
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OR):{
                                fingerprint = OrderScheme.OPE_query_detect(fields[0].toString(), this.orKey);
                                long last_send_instant = System.nanoTime();
                                OrderScheme.OPE_query_run(fingerprint, fingerprint);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            case (ProtectionVector.OR_ORE):{
                                long last_send_instant = System.nanoTime();
                                fingerprint = OREOrderScheme.ORE_query_detect(fields[0].toString(),this.or_OreKey);
                                OREOrderScheme.ORE_query_run(fingerprint,fingerprint);
                                st.store(System.nanoTime() - last_send_instant);
                                break;
                            }
                            default:{
                                break;
                            }
                        }
                        
                        //if (i % 50 == 0) {
                        //    System.out.println("Tuple: " + res[i].toStringTuple());
                        //}
                    } else if (opType == DepSpaceOperation.INP) {
                        //primeiro fazer os n outs
                        
                        //int index = rand.nextInt(maxIndex);
                        long last_send_instant = System.nanoTime();

                        res[i] = a.inp(template, getContext(a));
                        //System.out.println(a.inp(template,getContext(a)));
                        st.store(System.nanoTime() - last_send_instant);
                        if (i % 50 == 0) {
                            System.out.println("Tuple: " + res[i].toStringTuple());
                            initINPExp(a);
                        }

                    }

                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (id == initId) {
                System.out.println(this.id + " // 90th percentile for " + numberOfOps + " executions = " + st.getPercentile(90) / 1000 + " us ");

                System.out.println(this.id + " // Average time for " + numberOfOps + " executions (-10%) = " + st.getAverage(true) / 1000 + " us ");
                System.out.println(this.id + " // Standard desviation for " + numberOfOps + " executions (-10%) = " + st.getDP(true) / 1000 + " us ");
                System.out.println(this.id + " // Average time for " + numberOfOps + " executions (all samples) = " + st.getAverage(false) / 1000 + " us ");
                System.out.println(this.id + " // Standard desviation for " + numberOfOps + " executions (all samples) = " + st.getDP(false) / 1000 + " us ");
                //System.out.println(this.id + " // Maximum time for " + numberOfOps / 2 + " executions (all samples) = " + st.getMax(false) / 1000 + " us ");
            }

        }

    }
}
