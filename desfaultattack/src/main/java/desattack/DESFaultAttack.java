package desattack;

import java.math.BigInteger;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implémentation de l'attaque par faute sur le DES
 */
public class DESFaultAttack { 

    /**
     * Brute-force les 256 complétions de k16, décrypte le ciphertext corrigé
     * et compare au plaintext attendu.
     */
    public static void recoverFullKey(String k16) throws Exception {
        String partial56 = DESGeneralFunctions.revPC2(k16);
        System.out.println("-> partial56 (avec x)   : " + partial56);

        for (int i = 0; i < 256; i++) {
            //Reconstruire la clé candidate
            String k56filled = DESGeneralFunctions.replaceUnknownBits(partial56, i);
            String k64noPar  = DESGeneralFunctions.revPC1(k56filled);
            String k64bin    = DESGeneralFunctions.addParityBits(k64noPar);
            BigInteger bi    = new BigInteger(k64bin, 2);
            byte[] keyBytes  = bi.toByteArray();

            //S'assurer d'avoir exactement 8 octets
            if (keyBytes.length > 8) {
                keyBytes = Arrays.copyOfRange(keyBytes, keyBytes.length - 8, keyBytes.length);
            } else if (keyBytes.length < 8) {
                byte[] tmp = new byte[8];
                System.arraycopy(keyBytes, 0, tmp, 8 - keyBytes.length, keyBytes.length);
                keyBytes = tmp;
            }

            //Décryptage DES/ECB/NoPadding
            Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
            des.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
            byte[] cipherBytes = new BigInteger(DESGeneralFunctions.CIPHER_CORR_HEX, 16).toByteArray();
            byte[] plainBytes  = des.doFinal(cipherBytes);

            //Format hex du résultat
            String decryptedHex = String.format("%16s",
                    new BigInteger(1, plainBytes).toString(16))
                .replace(' ', '0')
                .toUpperCase();

            if (decryptedHex.equalsIgnoreCase(DESGeneralFunctions.PLAINTEXT_HEX)) {
                System.out.println(">> Clé trouvée pour i=" + i);
                System.out.println("   56-bit (filled) : " + k56filled);
                System.out.println("   64-bit no parité: " + k64noPar);
                System.out.printf("Clé trouvée : %016X%n", new BigInteger(1, keyBytes));
                return;
            }
        }
        System.out.println("Aucune clé n'a permis d'obtenir le plaintext attendu.");
    }
}
