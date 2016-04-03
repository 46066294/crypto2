import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

/**
 * Created by Mat on 03/04/2016.
 */
public class Utils {


    public static boolean areKeysPresent(KeyPair keyPair, PrivateKey prik) {
        if(keyPair != null && prik != null){
            return  true;
        }
        return false;
    }

    public static KeyPair generateKey(int keySize, String algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(keySize);
        KeyPair keys = keyGen.genKeyPair();

        return keys;
    }

    public static byte[] digestiona(File f, String algoritme, Key prik) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {

        FileInputStream ficheroStream = new FileInputStream(f);
        byte[] data = new byte[(int)f.length()];
        int tamanyArrayData = ficheroStream.read(data);

        Cipher cipher = Cipher.getInstance(algoritme ,"SunJCE");

        cipher.init(Cipher.ENCRYPT_MODE, prik);

        cipher.doFinal(data);

        return  data;
    }


    public static byte[] signar(byte[] digestionat, PrivateKey prik) throws SignatureException,
                                                                            InvalidKeyException,
                                                                            NoSuchAlgorithmException {
        //byte[] data = text.getBytes();
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(prik);
        signer.update(digestionat);
        byte[] signature = signer.sign();

        return signature;
    }

    public static File read(File f) {
        return f;
    }

    public static void write(String str, byte[] byteArray) {

    }

    public static byte[] concatenateByteArrays(File read, byte[] encryptdigestionat) {
        return new byte[0];
    }
}
