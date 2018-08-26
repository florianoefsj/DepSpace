package depspace.confidentiality;

import bftsmart.tom.core.messages.TOMMessage;
import depspace.general.DepSpaceReply;
import depspace.general.DepTuple;
import java.util.List;

/**
 *
 * @author alysson
 */
public class InvalidDepTuple extends DepTuple {

	/*private DepSpaceReply[] responses;
	private ProtectionVector vector;
	private int[] from;

	
	public InvalidDepTuple(DepSpaceReply[] responses, int[] from, ProtectionVector vector) {
		this.responses = responses;
		this.vector = vector;
		this.from = from;
	}

	public DepSpaceReply[] getResponses(){
		return this.responses;
	}

	public ProtectionVector getProtectionVector(){
		return this.vector;
	}

	public int[] getFrom(){
		return from;
	}*/
    
    private List<TOMMessage> responses;
    private ProtectionVector vector;

    /** Creates a new instance of InvalidDepTuple */
    public InvalidDepTuple(List<TOMMessage> responses, ProtectionVector vector) {
       this.responses = responses;
       this.vector = vector;
       this.fields = new Object[1];
       this.fields[0] = "INVALID TUPLE";
    }
    
    public List<TOMMessage> getResponses(){
           return this.responses;
    }

    public ProtectionVector getProtectionVector(){
        return this.vector;
    }

}

