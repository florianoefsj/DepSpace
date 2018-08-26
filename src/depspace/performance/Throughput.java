/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.performance;

import bftsmart.reconfiguration.ReconfigureReply;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.TOMSender;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.TOMUtil;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import depspace.confidentiality.ConfidentialityScheme;
import depspace.confidentiality.DeterministicScheme;
import depspace.confidentiality.OREOrderScheme;
import depspace.confidentiality.OperableScheme;
import depspace.confidentiality.ProtectionVector;
import depspace.general.Context;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepSpaceProperties;
import depspace.general.DepSpaceReply;
import depspace.general.DepSpaceRequest;
import depspace.general.DepTuple;
import static depspace.performance.Latency.tsName;
import depspace.util.BallotBox;
import depspace.util.Payload;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import pvss.InvalidVSSScheme;
import pvss.PVSSEngine;
import pvss.PublicInfo;

/**
 *
 * @author eduardo
 */
//public class Throughput extends TOMSender implements TSReceiver {
public class Throughput extends TOMSender {

    int id;
    int numberOfOps;
    DepSpaceOperation opType;

    int fieldsTyple = 0;

    private PaillierPrivateKey priv;
    private PaillierPublicKey pub;

    private String cdKey;
    private String orKey;
    private String or_OreKey;

    private ConfidentialityScheme scheme;
    private PreProcessedRequest[] msgsOut;
    private PreProcessedRequest[] msgsRead;
    private String tsName;

  
    private int size = 3;
    //private TSCommunicationSystem cs;
    //private TSConfiguration config;

    private final AtomicInteger sequenceNumber = new AtomicInteger();

    public class PreProcessedRequest{
         byte[] requestBytes;
         int reqId;
         int opId;
         TOMMessageType type;

        public PreProcessedRequest(byte[] requestBytes, int reqId, int opId, TOMMessageType type) {
            this.requestBytes = requestBytes;
            this.reqId = reqId;
            this.opId = opId;
            this.type = type;
        }
         
         
        
    }
    
    public Throughput(int numberOfOps, DepSpaceOperation opType, int fieldType, int size) {
        id = 7001;
        tsName = "Teste";
        this.numberOfOps = numberOfOps;
        DepSpaceConfiguration.init(null);
        init(id, DepSpaceConfiguration.configHome);
        initialize(numberOfOps, opType, fieldType, size);
        
    }
    
     private synchronized void executeOperation(PreProcessedRequest r) throws DepSpaceException {
         TOMulticast(r.requestBytes, r.reqId, r.opId, r.type);
     }

    private synchronized void executeOperation(DepSpaceOperation operation, Object arg, Context ctx) throws DepSpaceException {
        
        TOMMessageType type = operation.getRequestType();
        DepSpaceRequest request = new DepSpaceRequest(sequenceNumber.getAndIncrement(), operation, arg, ctx);
        byte[] requestBytes = request.serialize();

        int requestID = generateRequestId(type);
        int operationID = generateOperationId();
        TOMulticast(requestBytes, requestID, operationID, type);

    }

   

    
    @Override
    public void replyReceived(TOMMessage reply) {
      //não faz nada
    }
    
   
    private void initialize(int num, DepSpaceOperation opType, int fieldType, int size) {
        priv = OperableScheme.generatePrivateKey(3072);
        pub = OperableScheme.generatePublicKey(priv);
        or_OreKey = OREOrderScheme.ORE_keygenerate(32);
        orKey = DeterministicScheme.Det_keygenerate(16);
        cdKey = DeterministicScheme.Det_keygenerate(32);

        this.fieldsTyple = fieldType;
        this.opType = opType;
        this.size = size;
        
        this.msgsOut = new PreProcessedRequest[num];
        this.msgsRead = new PreProcessedRequest[num];
        
        try {
            PublicInfo publicInfo = new PublicInfo(DepSpaceConfiguration.n,
                    DepSpaceConfiguration.f + 1, DepSpaceConfiguration.groupPrimeOrder,
                    DepSpaceConfiguration.generatorg, DepSpaceConfiguration.generatorG);
            PVSSEngine engine = PVSSEngine.getInstance(publicInfo);
            this.scheme = new ConfidentialityScheme(engine.getPublicInfo(), DepSpaceConfiguration.publicKeys);
        } catch (Exception e) {
            e.printStackTrace();
        }

        //CRIAR O ESPAÇO
        
        Properties prop = DepSpaceProperties.createDefaultProperties(tsName);

        prop.put(DepSpaceProperties.DPS_CONFIDEALITY, "true");
        
        
        
        Context createContext = Context.createDefaultContext(tsName, DepSpaceOperation.CREATE, false, (DepTuple[]) null);
        try {
            executeOperation(DepSpaceOperation.CREATE, prop, createContext);
        } catch (DepSpaceException ex) {
           ex.printStackTrace();
        }
    }
    

    //abstract method of TOMSender
    public void TOMReplyReceive(Object msg) {
    }

    //public static int op =
    //public static boolean stop = false;
    @SuppressWarnings("static-access")
    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: ... Throughput <number of operations> <operation type> <field type> <size>");
            System.exit(-1);
        }

        int numberOfOps = Integer.parseInt(args[0]);
        
        DepSpaceOperation opType = DepSpaceOperation.OUT;

        if (args[1].equalsIgnoreCase("inp")) {
            opType = DepSpaceOperation.INP;
        } else if (args[1].equalsIgnoreCase("rdp")) {
            opType = DepSpaceOperation.RDP;
        }

        int fieldsType = ProtectionVector.PU;
        if (args[2].equalsIgnoreCase("pr")) {
            fieldsType = ProtectionVector.PR;
        } else if (args[2].equalsIgnoreCase("co")) {
            fieldsType = ProtectionVector.CO;

        } else if (args[2].equalsIgnoreCase("cd")) {
            fieldsType = ProtectionVector.CD;

        } else if (args[2].equalsIgnoreCase("op")) {
            fieldsType = ProtectionVector.OP;

        } else if (args[2].equalsIgnoreCase("or")) {
            fieldsType = ProtectionVector.OR;

        } else if (args[2].equalsIgnoreCase("or_ore")) {
            fieldsType = ProtectionVector.OR_ORE;
        }


        int size = Integer.parseInt(args[3]);

        new Throughput(numberOfOps, opType, fieldsType, size).run();

        System.exit(0);
    }

    private void setUpRdp() {

        for (int i = 0; i < msgsRead.length; i++) {

            if (i % 50 == 0) {
                System.out.println("Preparing rdp " + i);
            }

            Object[] fields = new Object[this.size];
            for (int j = 0; j < this.size; j++) {
                fields[j] = "*";
            }

            if (this.fieldsTyple != ProtectionVector.PR && this.fieldsTyple != ProtectionVector.OP) {
                fields[0] = 0;

            }
            DepTuple template = DepTuple.createTuple(fields);

            Context ctx = getContext();
            template = generateFingerprint(ctx.protectionVectors[0], template);
            
           // executeOperation(DepSpaceOperation.OUT, tuple, ctx);
            DepSpaceOperation operation = DepSpaceOperation.RDP;
            TOMMessageType type = operation.getRequestType();
            DepSpaceRequest request = new DepSpaceRequest(sequenceNumber.getAndIncrement(), operation, template, ctx);
            byte[] requestBytes = request.serialize();

            int requestID = generateRequestId(type);
            int operationID = generateOperationId();
            
        

            msgsRead[i] = new PreProcessedRequest(requestBytes, requestID, operationID, type);
        }
    }
    
    private void setUpInp() {

        for (int i = 0; i < msgsRead.length; i++) {

            if (i % 50 == 0) {
                System.out.println("Preparing inp " + i);
            }

            Object[] fields = new Object[this.size];
            for (int j = 0; j < this.size; j++) {
                fields[j] = "*";
            }

            if (this.fieldsTyple != ProtectionVector.PR && this.fieldsTyple != ProtectionVector.OP) {
                fields[0] = 0;

            }
            DepTuple template = DepTuple.createTuple(fields);

            Context ctx = getContext();
            template = generateFingerprint(ctx.protectionVectors[0], template);
            
           
            DepSpaceOperation operation = DepSpaceOperation.INP;
            TOMMessageType type = operation.getRequestType();
            DepSpaceRequest request = new DepSpaceRequest(sequenceNumber.getAndIncrement(), operation, template, ctx);
            byte[] requestBytes = request.serialize();

            int requestID = generateRequestId(type);
            int operationID = generateOperationId();
            
        

            msgsRead[i] = new PreProcessedRequest(requestBytes, requestID, operationID, type);
        }
    }

    private final DepTuple generateFingerprint(final ProtectionVector protectionVector,
            final DepTuple template) {
        try {
            return DepTuple.createTuple(scheme.fingerprint(protectionVector,
                    template.getFields()));
        } catch (InvalidVSSScheme e) {
            e.printStackTrace();
        }
        return null;
    }

    private void setUpOut() {

        for (int i = 0; i < msgsOut.length; i++) {
            try {
                if (i % 50 == 0) {
                    System.out.println("Preparing out " + i);
                }
                DepTuple dt = get(0);
                Context ctx = getContext();
                dt = scheme.mask(ctx.protectionVectors[0], dt);
                DepSpaceOperation operation = DepSpaceOperation.OUT;
                TOMMessageType type = operation.getRequestType();
                DepSpaceRequest request = new DepSpaceRequest(sequenceNumber.getAndIncrement(), operation, dt, ctx);
                byte[] requestBytes = request.serialize();
                int requestID = generateRequestId(type);
                int operationID = generateOperationId();
                msgsOut[i] = new PreProcessedRequest(requestBytes, requestID, operationID, type);
            } catch (InvalidVSSScheme ex) {
                ex.printStackTrace();
            }
        }
    }

    private final Context getContext() {

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
        return new Context(this.tsName, vectors);

    }

    public void run() {

        if (opType == DepSpaceOperation.OUT) {
            setUpOut();
            //pause();
            //sendStart();
            sendOut();
        } else if (opType == DepSpaceOperation.RDP) {
            DepTuple dt = get(0);

            try {
                Context ctx = getContext();
                dt = scheme.mask(ctx.protectionVectors[0], dt);
                
                executeOperation(DepSpaceOperation.OUT, dt, ctx);
                
                
                
                
            } catch (Exception e) {
                e.printStackTrace();
            }
            //pause();
            setUpRdp();
            //sendStart();
            sendRead();
        } else if (opType == DepSpaceOperation.INP) {

            DepTuple dt = get(0);

            try {
                Context ctx = getContext();
                dt = scheme.mask(ctx.protectionVectors[0], dt);
                executeOperation(DepSpaceOperation.OUT, dt, ctx);
            } catch (Exception e) {
                e.printStackTrace();
            }

            //pause();
            setUpInp();
            //sendStart();
            sendInp();

        }
        
        try {
            synchronized(this){
                this.wait();
            }
        } catch (InterruptedException ex) {
           ex.printStackTrace();
        }
        
        System.out.println("All messages was sent.");
    }

    private void sendRead() {

        for (int i = 0; i < msgsRead.length; i++) {
            try {
                if (i % 50 == 0) {
                    System.out.println("Sending read " + i);
                }
                
                if (i % 50 == 0) {
                    synchronized (this) {
                        try {
                            System.out.println("Vai aguardar");
                            this.wait(50);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                executeOperation(msgsRead[i]);
            }catch (DepSpaceException ex) {
                ex.printStackTrace();
            }
        }
    }

    
    private void sendInp() {

        for (int i = 0; i < msgsRead.length; i++) {
            try {
                if (i % 50 == 0) {
                    System.out.println("Sending inp " + i);
                }
                
                if (i % 50 == 0) {
                    synchronized (this) {
                        try {
                            System.out.println("Vai aguardar");
                            this.wait(50);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                executeOperation(msgsRead[i]);
            }catch (DepSpaceException ex) {
                ex.printStackTrace();
            }
        }
    }

    
    private void sendOut() {
        for (int i = 0; i < msgsOut.length; i++) {
            try {
                if (i % 50 == 0) {
                    System.out.println("Sending out " + i);
                }
                if (i % 50 == 0) {
                    synchronized (this) {
                        try {
                            System.out.println("Vai aguardar");
                            this.wait(50);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                executeOperation(msgsOut[i]);
            } catch (DepSpaceException ex) {
                ex.printStackTrace();
            }
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

}
