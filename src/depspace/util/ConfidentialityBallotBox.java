/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package depspace.util;

import bftsmart.tom.core.messages.TOMMessage;
import depspace.confidentiality.ConfidentialityScheme;
import depspace.confidentiality.InvalidDepTuple;
import depspace.confidentiality.ProtectionVector;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceReply;
import depspace.general.DepTuple;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import pvss.InvalidVSSScheme;
import pvss.Share;

/**
 *
 * @author eduardo
 */
public class ConfidentialityBallotBox extends BallotBox<Integer, DepSpaceReply, TOMMessage> {

    protected ProtectionVector protectionVector;
    private ConfidentialityScheme scheme;
    private int n;
    private int f;

    protected List<TOMMessage> repliesMsgs;
    protected List<DepSpaceReply> replies;
    

    protected boolean fastRead = false;

    private DepSpaceReply decided = null;

    public ConfidentialityBallotBox() {
        super();
        this.repliesMsgs = new LinkedList<TOMMessage>();
        this.replies = new LinkedList<DepSpaceReply>();
        
    }
    
    public void init(int decisionThreshold, int n, int f, boolean fastRead, ProtectionVector pv, ConfidentialityScheme scheme) {
        super.init(decisionThreshold);
        this.n = n;
        this.f = f;
        this.fastRead = fastRead;
        this.protectionVector = pv;
        this.scheme = scheme;
        
    }
    
    public void setFastRead(boolean f){
        this.fastRead = f;
    }
    
    public void clear() {
        super.clear();
        repliesMsgs.clear();
        replies.clear();
        decided = null;
    }
    
    
    @Override
    public boolean add(Integer id, DepSpaceReply reply, TOMMessage ballot) {
        // Check whether 'id' has already cast a vote
        //System.out.println(id+" replied: "+reply.arg);
        if (ids.contains(id)) {
            return false;
        }
        // Mark that 'id' has cast a vote
        ids.add(id);
       
        // Count vote
        /* List<TOMMessage> ballots = votes.get(reply);
        if (ballots == null) {
            ballots = new ArrayList<TOMMessage>(n);
            votes.put(reply, ballots);
        }
        ballots.add(ballot);*/
        

        //EDSON
        if (protectionVector != null && reply.arg != null) {
                for (int i = 0; i < protectionVector.getLength(); i++) {
                    if (protectionVector.getType(i) == ProtectionVector.OP) {
                        
                        try{
                            ((DepTuple)reply.arg).getFields()[i] = scheme.extractOPField(protectionVector, 
                                                                ((DepTuple)reply.arg).getFields()[i].toString());
                        }catch(Exception ignore){
                            ignore.printStackTrace();
                            
                        }
                    }
                }
        }
        
        
        
        
        repliesMsgs.add(ballot);
        replies.add(reply);
        return true;
    }

    public DepSpaceReply getDecision() {
        checkDecided();
        return decided;
    }

    private int countReceivedNulls() {
        int count = 0;
        
        for (int i = 0; i < replies.size(); i++) {
            if (replies.get(i).arg == null) {
                count++;
            }
        }
        return count;
    }

    private void checkDecided() {
        
        /**
         * A principio, se tiver null >= waitNum, poder� retornar: 1. Out, que
         * retorna null dizendo q executou o out; 2. RDP ou INP, que retorna
         * null dizendo que n�o tem a tupla; 3. CAS, que retorna null dizendo
         * que inseriu a tupla.
         */
        if (countReceivedNulls() >= decisionThreshold) {

            for (int i = 0; i < replies.size(); i++) {
                if (replies.get(i).arg == null) {
                    this.decided = replies.get(i);
                    //return true;
                }
            }
            //System.out.println(waitNum + " liberou o resultado por null");
        } else if (ckeckReceived() >= decisionThreshold) {
            //long t = System.nanoTime();
            
            DepTuple resp = getResponse();
            //System.out.println("getResponse: "+resp);
            /* st.store(System.nanoTime() - t);
                if(st.getCount() == 1000){
                    System.out.println("Client extr media: "+st.getAverage(true));
                    System.out.println("Client extr dp: "+st.getDP(true));
                }*/
            if (resp != null) {
                this.decided = new DepSpaceReply(replies.get(0).operation,resp);
                //return true;
            }
            /*else {
                    System.out.println("não liberou o resultado NORNAL ");

                }*/
        } /*else if (fastRead && super.countReceived() >= decisionThreshold) {
            //System.out.println("liberou o resultado FAST");
            return true;
        }*/
    }
    
    
   
    
    private int ckeckReceived() {
        //int count = super.countReceived();
        if (checkResults()) {
            return getVoteCount();
        } else {
            return -1;
        }
    }

    //TODO: funciona só pra servidores ids de 0 até n
    private boolean checkResults() {
        int c = 0;
        for (int i = 0; i < n; i++) {
            if (ids.contains(i)) {
                c++;
            } else {
                c = 0;
            }
            if (c > f) {
                return true;
            }
        }
        return false;
    }
    
    

    public DepTuple getResponse() {
       

        List<DepTuple> candidateShares = extractCandidateResponse();
        
        //System.out.println("candidates: "+candidateShares.size());
        
        List<DepTuple> validCandidateShares = new LinkedList<DepTuple>();
        
       
        
        for (ListIterator<DepTuple> li = candidateShares.listIterator(); li.hasNext();) {
            DepTuple tuple = li.next();
            Share share = tuple.getShare();
            if (share != null) {
                validCandidateShares.add(tuple);
            }/*else{
                System.out.println("share é NULL");
            }*/
        }
        
         //System.out.println("validCandidateShares: "+validCandidateShares.size());
         
         //System.out.println("waiting: "+decisionThreshold);
         // System.out.println("f: "+f);
         // System.out.println("n: "+n);
        
        if (validCandidateShares.size() > f) {
            DepTuple tuple = validCandidateShares.get(0);
            Share[] shares = new Share[n];
            for (ListIterator<DepTuple> li = validCandidateShares.listIterator(); li.hasNext();) {
                Share share = li.next().getShare();
                shares[share.getIndex()] = share;
            }
            try {
                Object[] tupleContents = scheme.extractTuple(shares);

                if (scheme.verifyTuple(protectionVector, tuple.getFields(), tupleContents)) {

                    //EDSON
                    for (int i = 0; i < protectionVector.getLength(); i++) {
                        if (protectionVector.getType(i) == ProtectionVector.OP) {
                            //tupleContents[i] = scheme.extractOPField(protectionVector, tuple.getFields()[i].toString());
                            tupleContents[i] = tuple.getFields()[i];
                        }
                    }
                    return DepTuple.createTuple(tupleContents);
                } else {
                    //return new InvalidDepTuple(results,this.protectionVector);
                    return tryGetResponseAgain(candidateShares);
                }
            } catch (InvalidVSSScheme e) {
                //return new InvalidDepTuple(results,this.protectionVector);
                return tryGetResponseAgain(candidateShares);
            }
        } else if (!fastRead && (candidateShares.size() >= n - f)) {
            //return new InvalidDepTuple(results,this.protectionVector);
            return tryGetResponseAgain(candidateShares);
        }
        return null;
    }

    private DepTuple tryGetResponseAgain(List<DepTuple> candidateShares) {
        List<DepTuple> validCandidateShares = new LinkedList<DepTuple>();
        for (ListIterator<DepTuple> li = candidateShares.listIterator(); li.hasNext();) {
            DepTuple tuple = li.next();
            Share share = tuple.getShare();
            try {
                if (share != null && share.verify(scheme.getPublicInfo(),
                        scheme.getPublicKey(share.getIndex()))) {
                    validCandidateShares.add(tuple);
                }
            } catch (InvalidVSSScheme e) {
            }

        }
        if (validCandidateShares.size() > f) {
            DepTuple tuple = validCandidateShares.get(0);
            Share[] shares = new Share[n];
            for (ListIterator<DepTuple> li = validCandidateShares.listIterator(); li.hasNext();) {
                Share share = li.next().getShare();
                shares[share.getIndex()] = share;
            }
            try {
                Object[] tupleContents = scheme.extractTuple(shares);

                if (scheme.verifyTuple(protectionVector, tuple.getFields(), tupleContents)) {
                    //EDSON
                    for (int i = 0; i < protectionVector.getLength(); i++) {
                        if (protectionVector.getType(i) == ProtectionVector.OP) {
                            //tupleContents[i] = scheme.extractOPField(protectionVector, tuple.getFields()[i].toString());
                            tupleContents[i] = tuple.getFields()[i];

                        }
                    }

                    return DepTuple.createTuple(tupleContents);
                } else {
                    return new InvalidDepTuple(this.repliesMsgs, this.protectionVector);
                }
            } catch (InvalidVSSScheme e) {
                return new InvalidDepTuple(this.repliesMsgs, this.protectionVector);
            }
        } else if (!fastRead && (candidateShares.size() >= n - f)) {
            return new InvalidDepTuple(this.repliesMsgs, this.protectionVector);
        }
        return null;
    }

    private final List<DepTuple> extractCandidateResponse() {
        List<DepTuple> candidateShares = new LinkedList<DepTuple>();
        for (int i = 0; i < replies.size(); i++) {

                if (replies.get(i).arg instanceof DepTuple) {
                    DepTuple tuple1 = (DepTuple) replies.get(i).arg;
                    candidateShares.add(tuple1);
                    for (int j = i + 1; j < replies.size(); j++) {
                        

                        
                            if (replies.get(j).arg instanceof DepTuple) {

                                DepTuple tuple2 = (DepTuple) replies.get(j).arg;

                                if (theSame(tuple1, tuple2)) {
                                    candidateShares.add(tuple2);
                                }/*else{
                                    System.out.println(tuple1+" NÃO SÂO AS MESMAS"+tuple2);
                                }*/

                            } else if (replies.get(j).arg instanceof DepSpaceException) {
                                System.out.println("arg 2: " + replies.get(j).arg);
                            }

                        
                    }
                    if (candidateShares.size() >= this.decisionThreshold) {
                        return candidateShares;
                    } else {
                        candidateShares.clear();
                    }
                } else if (replies.get(i).arg instanceof DepSpaceException) {
                    System.out.println("arg 1: " + replies.get(i).arg);

                }
            
        }
        candidateShares.clear();
        return candidateShares;
    }

    private final boolean theSame(DepTuple tuple1, DepTuple tuple2) {
        return tuple1.equalFields(tuple2)
                //theSameFields(tuple1, tuple2) //same fingerprint
                && (tuple1.getPublishedShares().hashCode()
                == tuple2.getPublishedShares().hashCode()); //same published shares
    }
}
