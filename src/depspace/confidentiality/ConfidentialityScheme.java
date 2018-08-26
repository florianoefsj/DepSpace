package depspace.confidentiality;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import pvss.InvalidVSSScheme;
import pvss.PVSSEngine;
import pvss.PublicInfo;
import pvss.PublishedShares;
import pvss.Share;
import depspace.general.DepTuple;

/**
 * ConfidentialityScheme.
 *
 * @author	Alysson Bessani
 * @author2	Eduardo Alchieri
 * @author3	Rui Posse (ruiposse@gmail.com)
 * @version	DepSpace 2.0
 * @date
 */
public class ConfidentialityScheme {

    public static final String PRIVATE = "PR";
    //public static final String DELIM = "|";

    protected PVSSEngine engine;
    private PublicInfo info;
    private BigInteger[] publicKeys;

    private int id;
    private BigInteger secretKey;

    /**
     * Creates a new instance of the Confidentiality Scheme. This constructor
     * must be called at client side.
     */
    public ConfidentialityScheme(PublicInfo publicInfo, BigInteger[] publicKeys) throws InvalidVSSScheme {
        this.engine = PVSSEngine.getInstance(publicInfo);
        this.info = publicInfo;
        this.publicKeys = publicKeys;
    }

    /**
     * Creates a new instance of the Confidentiality Scheme. This constructor
     * must be called at server side.
     */
    public ConfidentialityScheme(PublicInfo publicInfo, BigInteger[] publicKeys,
            int id, BigInteger secretKey) throws InvalidVSSScheme {
        this(publicInfo, publicKeys);
        this.id = id;
        this.secretKey = secretKey;
    }

    public PublicInfo getPublicInfo() {
        return info;
    }

    public BigInteger[] getPublicKeys() {
        return publicKeys;
    }

    public BigInteger getPublicKey(int index) {
        return publicKeys[index];
    }

    public DepTuple mask(ProtectionVector protectionVector, DepTuple tuple) throws InvalidVSSScheme {

        Object[] fingerprint = fingerprint(protectionVector, tuple.getFields());

        PublishedShares shares
                = engine.generalPublishShares(tupleToBytes(tuple.getFields()), publicKeys);

        return DepTuple.internalCreateConfidentialTuple(tuple.getC_rd(),
                tuple.getC_in(), fingerprint, shares);
    }

    public DepTuple unmask(DepTuple tuple) throws InvalidVSSScheme {
//        DepTuple unmaskedTuple = DepTuple.internalCreateConfidentialTuple(
//          tuple.getC_rd(),tuple.getC_in(),tuple.getFields(), tuple.getPublishedShares());

        tuple.extractShare(id, secretKey, info, publicKeys);

        return tuple;
    }

    @SuppressWarnings("static-access")
    public boolean verifyTuple(ProtectionVector protectionVector,
            Object[] fingerprint,
            Object[] fields) throws InvalidVSSScheme {
        //System.out.println("Verify 1");
        if ((fingerprint.length != fields.length)
                || (protectionVector.getLength() != fields.length)) {
            //System.out.println("Verify 2");
            return false;
        }
        //System.out.println("Verify 3");
        for (int i = 0; i < protectionVector.getLength(); i++) {
            // if(!fingerprint[i].equals(WILDCARD)){
            //System.out.println("Verify 4-"+i);
            switch (protectionVector.getType(i)) {
                case ProtectionVector.PU: {
                    if (!fingerprint[i].equals(fields[i])) {
                        return false;
                    }
                }
                break;
                case ProtectionVector.CO: {
                    if (!fingerprint[i].equals(engine.hash(engine.getPublicInfo(),
                            fields[i].toString().getBytes()).toString())) {
                        return false;
                    }
                }
                break;
                case ProtectionVector.PR: {
                    if (!PRIVATE.equals(fingerprint[i])) {
                        return false;
                    }
                }
                break;
                //EDSON
                case ProtectionVector.CD: {
                    try {
                        //verificar se "batem" (fingerprint[i] e tupla.fields[i]) como o do hash
                        //usar protectionVector.CDKey
                        /* Escolha o uso:
                        1. DetEncrypt: HMAC+CypherText; 
                        2. HmacSHA256Str: somente HMAC.
                         */
                        if (!fingerprint[i].equals(DeterministicScheme.HmacSHA256Str(
                                fields[i].toString(), protectionVector.CDKey))) {
                            return false;
                        }
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
                break;
                case ProtectionVector.OR: {
                    String query = OrderScheme.OPE_query_detect(fields[i].toString(), protectionVector.ORKey);
                    if (!OrderScheme.OPE_query_run(fingerprint[i].toString(), query)) {
                        return false;
                    }
                }
                break;
                case ProtectionVector.OR_ORE: {
                    String received = OREOrderScheme.ORE_ciphertext_to_string(OREOrderScheme.ORE_encrypt(fields[i].toString(), protectionVector.OR_OreKey));
                    if (!OREOrderScheme.ORE_query_run(fingerprint[i].toString(), received)) {
                        return false;
                    }
                }
                break;
                case ProtectionVector.OP: {
                    //Como podem sofrer alterações, não tem como verificar e não tem sentido verificar. A segurança é
                    //garantida pela utilização do próprio valor do fingerprint.
                }
                break;
                default: {
                    throw new RuntimeException("Invalid field type specification");
                }
            }
            // }
        }

        return true;
    }

    //EDSON
    public double extractOPField(ProtectionVector pv, String text) {
        return OperableScheme.decrypt(pv.OPPrivateKey, OperableScheme.StringToEncrypted(text, pv.OPPublicKey));
    }

    public Object[] extractTuple(Share[] shares) throws InvalidVSSScheme {
        try {
            byte[] tupleBytes = engine.generalCombineShares(shares);

            return (Object[]) new ObjectInputStream(
                    new ByteArrayInputStream(tupleBytes)).readObject();
        } catch (Exception e) {
            throw new RuntimeException("cannot read tuple fields: " + e);
        }
    }

    @SuppressWarnings("static-access")
    public Object[] fingerprint(ProtectionVector protectionVector, Object[] fields)
            throws InvalidVSSScheme {

        if (protectionVector.getLength() != fields.length) {
            throw new RuntimeException("Invalid field type specification");
        }

        Object[] fingerprint = new Object[fields.length];

        for (int i = 0; i < protectionVector.getLength(); i++) {
            if (DepTuple.WILDCARD.equals(fields[i])) {
                fingerprint[i] = DepTuple.WILDCARD;
            } else {
                switch (protectionVector.getType(i)) {
                    case ProtectionVector.PU: {
                        fingerprint[i] = fields[i];
                    }
                    break;
                    case ProtectionVector.CO: {
                        fingerprint[i] = engine.hash(engine.getPublicInfo(),
                                fields[i].toString().getBytes()).toString();
                    }
                    break;
                    case ProtectionVector.PR: {
                        fingerprint[i] = PRIVATE;
                    }
                    break;
                    //EDSON
                    case ProtectionVector.CD: {
                        try {
                            /* Escolha o uso:
                            1. DetEncrypt: HMAC+CypherText; 
                            2. HmacSHA256Str: somente HMAC.
                             */
                            fingerprint[i] = DeterministicScheme.HmacSHA256Str(
                                    fields[i].toString(), protectionVector.CDKey);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                    break;
                    case ProtectionVector.OR: {
                        fingerprint[i] = OrderScheme.OPE_query_detect(fields[i].toString(), protectionVector.ORKey);
                    }
                    break;
                    case ProtectionVector.OR_ORE: {
                        //fingerprint[i] = OREOrderScheme.ORE_encrypt();
                        fingerprint[i] = OREOrderScheme.ORE_query_detect(fields[i].toString(),protectionVector.OR_OreKey);
                    }
                    break;
                    case ProtectionVector.OP: {
                        fingerprint[i] = OperableScheme.encryptedToString(
                                OperableScheme.encrypt(protectionVector.OPPublicKey, fields[i].toString()));
                    }
                    break;

                    default: {
                        throw new RuntimeException("Invalid field type specification");
                    }
                }
            }
        }

        return fingerprint;
    }

    private byte[] tupleToBytes(Object[] fields) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);

        try {
            new ObjectOutputStream(bos).writeObject(fields);

            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("cannot write tuple fields: " + e);
        }
    }

}
