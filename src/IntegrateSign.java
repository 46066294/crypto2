import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class IntegrateSign {

    private static final File OUT_FILE = new File("secureMsg.rsa");

    private static final File SRC_KEYSTORE_FILE = new File("origen.jks");

    private static final char[] PASSWORD =  "password".toCharArray();

    private static final String SRC_ALIAS = "origen";

    private static final String DST_CERT_ALIAS = "desticert";


    public KeyStore loadKeyStore() throws Exception {
        KeyStore myStore = KeyStore.getInstance("JKS");
        myStore.load(new FileInputStream(SRC_KEYSTORE_FILE), PASSWORD);
        if (myStore.containsAlias(SRC_ALIAS) && myStore.isKeyEntry(SRC_ALIAS)) {
            return myStore;
        }
        return null;
    }



    public void generate(String text) throws Exception {
        //Obtenir dades del magatzem
        KeyStore myStore = loadKeyStore();

        PrivateKey origKey = (PrivateKey)myStore.getKey(SRC_ALIAS, PASSWORD);
        X509Certificate dstCert = (X509Certificate)myStore.getCertificate(DST_CERT_ALIAS);
        PublicKey dstPubKey = dstCert.getPublicKey();

        //Signar
        byte[] data = text.getBytes();
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(origKey);
        signer.update(data);
        byte[] signature = signer.sign();

        //Ara cal ajuntar-ho tot
        byte[] result = new byte[signature.length + data.length];
        int i = 0;
        while (i < signature.length) {
            result[i] = signature [i];
            i++;
        }
        int j = 0;
        while (j < data.length) {
            result[i] = data [j];
            j++;
            i++;
        }

        //Xifrat embolcallat. Les dades a xifrar són a "result"
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey sKey = kgen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sKey);
        byte[] encMsg = cipher.doFinal(result);

        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, dstPubKey);
        byte[] encKey = cipher.wrap(sKey);

        //Desar tot a fitxer
        //El primer que escriurem és la mida de la clau, per poder discriminar clau de dades
        try (FileOutputStream out = new FileOutputStream(OUT_FILE)) {
            out.write(encKey);
            out.write(encMsg);
        }
    }

    /** Programa que signa i xifra (wrapped) un text de mida arbitrària.
     */
    public static void main(String[] args) throws Exception {
        IntegrateSign act = new IntegrateSign();

        Scanner scan = new Scanner(System.in);
        System.out.print("Escriu el text a protegir: ");
        String text = scan.nextLine();

        act.generate(text);
        System.out.println("El procés ha finalitzat correctament.");
    }
}