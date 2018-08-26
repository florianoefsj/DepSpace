package depspace.server;

import bftsmart.tom.util.Storage;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import depspace.general.Context;
import depspace.general.DepSpace;
import depspace.general.DepTuple;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DepSpaceListImpl implements DepSpace {
    


     public static final String INCREMENT_OPERATION = "increment";

    private static final DepTuple TEMPLATE = DepTuple.createTuple(INCREMENT_OPERATION, DepTuple.WILDCARD);




     // The tuple list

    protected final List<DepTuple> tuplesBag;

    // Flag to show whether it is possible to renew an expired tuple
    // true - it is possible
    // false - it is not possible
    protected final boolean realTimeRenew;

    private PrintWriter pw;
    private long start = 0;
    private int interval = 100;
    private long throughputMeasurementStartTime = System.currentTimeMillis();
    private int iterations = 0;
    private float maxTp = -1;
    
    public DepSpaceListImpl(boolean realTimeRenew) {
        
        //System.out.println("CRIOU UMA DEPIMPL LAYER");
        this.tuplesBag = new LinkedList<DepTuple>();
        this.realTimeRenew = realTimeRenew;
        
        try {
            File f = new File("resultado_" + System.nanoTime() + ".txt");
            FileWriter fw = new FileWriter(f);
            pw = new PrintWriter(fw);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        
    }

    @Override
    public void out(DepTuple tuple, Context ctx) {
        tuplesBag.add(tuple);
        //System.out.println("out: "+tuple );
        //computeStatistics();
    }

    @Override
    public DepTuple renew(DepTuple template, Context ctx) {
        for (Iterator<DepTuple> iterator = tuplesBag.iterator(); iterator.hasNext();) {
            DepTuple tuple = iterator.next();
            if (!tuple.canIn(ctx.invokerID)) {
                continue;
            }
            if (!tuple.matches(template)) {
                continue;
            }
            if (tuple.isExpired(ctx.time) && !realTimeRenew) {
                return null;
            }
            tuple.setExpirationTime(template.getExpirationTime());
            return tuple;
        }
        return null;
    }

    @Override
    public DepTuple rdp(DepTuple template, Context ctx) {
        for (Iterator<DepTuple> iterator = tuplesBag.iterator(); iterator.hasNext();) {
            DepTuple tuple = iterator.next();
            if(tuple == null){
                continue;
            }
            if (!tuple.canRd(ctx.invokerID)) {
                continue;
            }
            if (!tuple.matches(template)) {
                continue;
            }
            if (!tuple.isExpired(ctx.time)) {
                return tuple;
            }
            iterator.remove();
        }
        return null;
    }
    
    
    // #############
    // # EXECUTION #
    // #############
    //@Override
    public DepTuple inp_contador(DepTuple template, Context ctx)  {
        // Get and increment
        DepTuple tuple = inp(TEMPLATE, ctx);
        //System.out.println("leu: "+tuple );
        if (tuple == null) {
            return null;
        }
        int counterValue = (Integer) tuple.getFields()[1];
        out(DepTuple.createTuple(INCREMENT_OPERATION,counterValue + 1),ctx);
        return tuple;
    }


    public DepTuple inp(DepTuple template, Context ctx) {
        
        for (Iterator<DepTuple> iterator = tuplesBag.iterator(); iterator.hasNext();) {
            DepTuple tuple = iterator.next();
            if (!tuple.canIn(ctx.invokerID)) {
                continue;
            }
            if (!tuple.matches(template)) {
                continue;
            }
            iterator.remove();
            if (!tuple.isExpired(ctx.time)) {
                return tuple;
            }
        }
        return null;
    }

    @Override
    public DepTuple cas(DepTuple template, DepTuple tuple, Context ctx) {
        DepTuple result = rdp(template, ctx);
        if (result == null) {
            out(tuple, ctx);
        }
        return result;
    }

    public void computeStatistics() {
        if (start == 0) {
            start = System.currentTimeMillis();
            throughputMeasurementStartTime = start;
        }

        iterations++;

        float tp = -1;
        if (iterations % interval == 0) {
            

            System.out.println("--- Measurements after " + iterations + " ops (" + interval + " samples) ---");

            tp = (float) (interval * 1000 / (float) (System.currentTimeMillis() - throughputMeasurementStartTime));

            if (tp > maxTp) {
                maxTp = tp;
            }

            int now = (int) ((System.currentTimeMillis() - start) / 1000);
            System.out.println("Throughput = " + tp + " operations/sec at sec: " + now + " (Maximum observed: " + maxTp + " ops/sec)");

          
            pw.println(now + " " + tp);
            
            pw.flush();

            throughputMeasurementStartTime = System.currentTimeMillis();
        }

    }

    @Override
    public DepTuple replace(DepTuple template, DepTuple tuple, Context ctx) {
        //System.out.println("---REPLACE---");
        
        DepTuple result = inp(template, ctx);
        if (result == null) {
            return result;
        }
        //computeStatistics();//conta uma operação a mais
        out(tuple, ctx);
        return result;
    }

    @Override
    public void outAll(List<DepTuple> tuplesBag, Context ctx) {
        this.tuplesBag.addAll(tuplesBag);
    }

    @Override
    public Collection<DepTuple> rdAll() {
        return new ArrayList<DepTuple>(tuplesBag);
    }

    @Override
    public Collection<DepTuple> rdAll(DepTuple template, Context ctx) {
        ArrayList<DepTuple> result = new ArrayList<DepTuple>();
        int tuplesToRead = (template.getN_Matches() > 0) ? template.getN_Matches() : tuplesBag.size();
        for (Iterator<DepTuple> iterator = tuplesBag.iterator(); iterator.hasNext() && (tuplesToRead > 0);) {
            DepTuple tuple = iterator.next();
            if (!tuple.canRd(ctx.invokerID)) {
                continue;
            }
            if (!tuple.matches(template)) {
                continue;
            }
            if (tuple.isExpired(ctx.time)) {
                iterator.remove();
                continue;
            }
            result.add(tuple);
            tuplesToRead--;
        }
        return result;
    }

    @Override
    public Collection<DepTuple> inAll(DepTuple template, Context ctx) {
        ArrayList<DepTuple> result = new ArrayList<DepTuple>();
        int tuplesToRead = (template.getN_Matches() > 0) ? template.getN_Matches() : tuplesBag.size();
        for (Iterator<DepTuple> iterator = tuplesBag.iterator(); iterator.hasNext() && (tuplesToRead > 0);) {
            DepTuple tuple = iterator.next();
            if (!tuple.canIn(ctx.invokerID)) {
                continue;
            }
            if (!tuple.matches(template)) {
                continue;
            }
            iterator.remove();
            if (tuple.isExpired(ctx.time)) {
                continue;
            }
            result.add(tuple);
            tuplesToRead--;
        }
        return result;
    }

    /**
     * *********************
     * BLOCKING OPERATIONS *
	 **********************
     */
    @Override
    public DepTuple rd(DepTuple template, Context ctx) {
        throw new UnsupportedOperationException("Not implemented at this layer");
    }

    @Override
    public DepTuple in(DepTuple template, Context ctx) {
        throw new UnsupportedOperationException("Not implemented at this layer");
    }

}
