import com.sun.org.apache.xpath.internal.SourceTree;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;


public class P01_part1 {

    public static final String PRIVATE_KEY_FILE = "private.key";
    public static final String FITXER_PLA = "Sparring.txt";
    public static final String FITXER_SIGNAT = "firmat.txt";
    public static final Integer KEYSIZE = 1216;
    public static final String ALGORITHM = "RSA";

    public static void main(String[] args) throws IOException,
                                                NoSuchAlgorithmException,
                                                ClassNotFoundException,
                                                NoSuchPaddingException,
                                                InvalidAlgorithmParameterException,
                                                IllegalBlockSizeException,
                                                BadPaddingException,
                                                NoSuchProviderException,
                                                InvalidKeyException,
                                                SignatureException {

        KeyPair keyPair = null;
        PrivateKey prik = null;

        File f = new File(FITXER_PLA);

        if(!Utils.areKeysPresent(keyPair, prik)){
            keyPair = Utils.generateKey(KEYSIZE, ALGORITHM);
            prik = keyPair.getPrivate();
        }else{
            ObjectInputStream inputStream = null;
            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            prik = (PrivateKey) inputStream.readObject();
        }

        byte[] digestionat = Utils.digestiona(f,"AES/CBC/PKCS5Padding (128)", prik);

        byte[] encryptdigestionat = Utils.signar(digestionat,prik);
        System.out.println("Longitud del fitxer: "+f.length());
        System.out.println("Longitud de la firma: "+encryptdigestionat.length);
        Utils.write(FITXER_SIGNAT,Utils.concatenateByteArrays(Utils.read(f),encryptdigestionat));
    }

}
