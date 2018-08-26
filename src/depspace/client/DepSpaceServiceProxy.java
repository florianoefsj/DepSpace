package depspace.client;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import bftsmart.reconfiguration.ReconfigureReply;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.TOMSender;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.Logger;
import bftsmart.tom.util.TOMUtil;
import depspace.confidentiality.ConfidentialityScheme;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceOperation;
import depspace.general.DepSpaceReply;
import depspace.general.DepSpaceRequest;
import depspace.util.BallotBox;
import depspace.util.ConfidentialityBallotBox;
import depspace.util.Payload;

public class DepSpaceServiceProxy extends TOMSender {

    private final BlockingQueue<TOMMessage> queue;
    private final BallotBox<Integer, Payload, TOMMessage> replyBallotBox;
    private final BallotBox<Integer, Payload, TOMMessage> blockingBallotBox;

    private ConfidentialityBallotBox confBallotBox;

    public DepSpaceServiceProxy(int processID) {
        this.queue = new LinkedBlockingQueue<TOMMessage>();
        this.replyBallotBox = new BallotBox<Integer, Payload, TOMMessage>();
        this.blockingBallotBox = new BallotBox<Integer, Payload, TOMMessage>();

        this.confBallotBox = new ConfidentialityBallotBox();

        init(processID, DepSpaceConfiguration.configHome);
    }

    @Override
    public void replyReceived(TOMMessage reply) {
        queue.add(reply);
    }

    public synchronized byte[] invoke(byte[] request, TOMMessageType reqType, DepSpaceRequest req) {
        while (true) {
            // Send request and obtain stable reply
            TOMMessage reply = invokeService(request, reqType, req);

            // Everything is fine if the stable reply is from the current view 
            byte[] result = reply.getContent();
            if (reply.getViewID() == getViewManager().getCurrentViewId()) {
                return result;
            }

            // Reconfigure if the system switched to a new view
            if (reqType == TOMMessageType.ORDERED_REQUEST) {
                reconfigureTo((View) TOMUtil.getObject(result));
            } else {
                Object r = TOMUtil.getObject(result);
                if (r instanceof View) {
                    // Did not executed the request because it is using an outdated view
                    reconfigureTo((View) r);
                } else {
                    // Reconfiguration executed!
                    reconfigureTo(((ReconfigureReply) r).getView());
                    return result;
                }
            }
        }
    }

    private TOMMessage invokeService(byte[] request, TOMMessageType reqType, DepSpaceRequest req) {
        // Send request
        int requestID = generateRequestId(reqType);
        int operationID = generateOperationId();
        TOMulticast(request, requestID, operationID, reqType);

        try {
            // Prepare ballot boxes
            replyBallotBox.init(getReplyQuorum());
            blockingBallotBox.init(getReplyQuorum());

            confBallotBox.init(getReplyQuorum(), getViewManager().getCurrentViewN(),
                    getViewManager().getCurrentViewF(),
                    (reqType == TOMMessageType.UNORDERED_REQUEST), req.context.protectionVectors[0], req.context.scheme);

            // Wait for a stable result
            boolean retry = true;
            long deadline = System.currentTimeMillis() + DepSpaceConfiguration.clientRetransmissionTimeout;
            while (true) {
                TOMMessage reply = queue.poll(deadline - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
                if (reply == null) {
                    // Resend request and reset timeout
                    if (retry) {
//						System.err.println("Retry invocation for request {" + getProcessId() + ", " + requestID + ", " + operationID + "}");
                        TOMulticast(request, requestID, operationID, reqType);
                    }
                    deadline = System.currentTimeMillis() + DepSpaceConfiguration.clientRetransmissionTimeout;
                    continue;
                }

                // Check reply
                if (reply.getSequence() != requestID) {
                    continue;
                }
                if (reply.getOperationId() != operationID) {
                    continue;
                }
                if (reply.getReqType() != reqType) {
                    continue;
                }

                // Only consider replies that come from replicas
                int pos = getViewManager().getCurrentViewPos(reply.getSender());
                if (pos < 0) {
                    continue;
                }

                Payload payload = new Payload(reply.getContent());
                //TODO: se operation for create ou delete tratar como não confidencialidade
                if (req.context.scheme == null || req.operation == DepSpaceOperation.CREATE || req.operation == DepSpaceOperation.DELETE) {
                    // Add reply to the associated ballot box

                    BallotBox<Integer, Payload, TOMMessage> ballotBox = payload.matches(TOMMessage.BLOCKING_HINT) ? blockingBallotBox : replyBallotBox;
                    boolean success = ballotBox.add(reply.getSender(), payload, reply);
                    if (!success) {
                        continue;
                    }

                    // Check decision
                    Payload decision = ballotBox.getDecision();
                    if (decision != null) {
                        // Return regular reply
                        if (ballotBox == replyBallotBox) {
                            return replyBallotBox.getDecidingBallots().get(0);
                        }
                        // Process blocking hint
                        retry = false;
                        continue;
                    }

                    // Handle corner cases
                    if (ballotBox.getVoteCount() < getViewManager().getCurrentViewN()) {
                        continue;
                    }

                } else {
                    try {
                        boolean success = confBallotBox.add(reply.getSender(), new DepSpaceReply(payload.payload), reply);
                        
                        if (!success) {
                            continue;
                        }

                        DepSpaceReply r = confBallotBox.getDecision();
                        //System.out.println("getDecision() resposta: "+r);
                        if (r != null) {
                            return new TOMMessage(0, 0, 0, r.serialize(), reply.getViewID(), reply.getReqType());
                        }
                        
                        //System.out.println(getViewManager().getCurrentViewN()+" numero recebido: "+confBallotBox.getVoteCount());

                        // Handle corner cases
                        if (confBallotBox.getVoteCount() < getViewManager().getCurrentViewN()) {
                            continue;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }

                if (reqType == TOMMessageType.ORDERED_REQUEST) {
                    throw new RuntimeException("Received n-f replies without f+1 of them matching.");
                }
                
                
                //System.out.println("REINICIANDO!!!");

                // Invoke read-only operation as an ordered operation
                reqType = TOMMessageType.ORDERED_REQUEST;
                requestID = generateRequestId(reqType);
                operationID = generateOperationId();
                replyBallotBox.clear();
                blockingBallotBox.clear();
                
                confBallotBox.clear();
                confBallotBox.setFastRead(false);
                
                deadline = System.currentTimeMillis();
//				System.err.println("Retry invocation for request {" + getProcessId() + ", " + requestID + ", " + operationID + "} --> " + reqType);
            }
        } catch (InterruptedException ie) {
            return null;
        }
    }

    private int getReplyQuorum() {
        if (getViewManager().getStaticConf().isBFT()) {
            return (int) Math.ceil((getViewManager().getCurrentViewN() + getViewManager().getCurrentViewF()) / 2) + 1;
        }
        return (int) Math.ceil((getViewManager().getCurrentViewN()) / 2) + 1;
    }

    private void reconfigureTo(View v) {
        Logger.println("Installing a most up-to-date view with id=" + v.getId());
        getViewManager().reconfigureTo(v);
        getCommunicationSystem().updateConnections();
    }

}
