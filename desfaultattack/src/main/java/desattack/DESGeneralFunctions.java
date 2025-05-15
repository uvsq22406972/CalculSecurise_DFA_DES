package desattack;

import java.math.BigInteger;
import java.util.*;

    /**
     * Méthodes générales pour l'attaque par faute sur le DES
     */
    public class DESGeneralFunctions {
        public static final String PLAINTEXT_HEX = "BA7337581520D580";
        public static final String CIPHER_CORR_HEX = "2E896E215F489531";
        public static final String IV_HEX = "0000000000000000";
        public static final String MODE = "ecb";
        public static final String ACTION = "Decrypt";

        public static final long[] CIPHER_FAULTY_HEX = {
            0x27996E665F5C9531L, 0x6E897E215B089D79L, 0x3A092F215E48F131L, 0x2FCD6A654DC89521L, 
            0x6FC97A6549489578L, 0x6E89FE391F4CD531L, 0x2FC94A215F4A8571L, 0x4E096E215A48C030L,
            0x2C886EE55E499121L, 0x2E896A200F589733L, 0x6EA96E215B088C70L, 0x2A8D6F31DE68D135L,
            0x2F8D6E308E58D137L, 0x2FD94E674F488571L, 0x2E8D66205FD89521L, 0x26E96A205B5C8471L,
            0xBE896F115A48C571L, 0x2E9C6E255F4815A1L, 0x2FC16E214F5C9731L, 0x7A897F217F408571L,
            0x3A9C6F257F4885F5L, 0x2E8D66A05E589135L, 0x2A996D655F699531L, 0x2C846E655F5D9531L, 
            0x4E897E291B0C8430L, 0x2A896E315E48B111L, 0x2E9B6E615F481525L, 0x6FC96A20571E9531L,
            0x6A892F30561C9111L, 0x2A992C455B498571L, 0x6E89FE315F40D531L, 0xBA9B2E715E48D531L 
        };

        //Les variables DES connus
        public static final int[] PC1 = {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        };
        public static final int[] PC2 = {
            14,17,11,24,1,5,3,28,15,6,21,10,
            23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,
            44,49,39,56,34,53,46,42,50,36,29,32
        };
        public static final int[] IP = {
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
        };
        //Inverse IP
        public static final int[] revIP = {
            40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
        };

        public static final int[] P = {
            16,7,20,21,29,12,28,17,
             1,15,23,26,5,18,31,10,
             2,8,24,14,32,27,3,9,
            19,13,30,6,22,11,4,25
        };
        //Inverse P
        public static final int[] revP = {
            9,17,23,31,13,28,2,18,
            24,16,30,6,26,20,10,1,
            8,14,25,3,4,29,11,19,
            32,12,22,7,5,27,15,21
        };
        //Expansion E (32 à 48 bits)
        public static final int[] E = {
            32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
            12,13,14,15,16,17, 16,17,18,19,20,21,
            20,21,22,23,24,25, 24,25,26,27,28,29,
            28,29,30,31,32,1
        };

        // S-box
        public static final int[][][] SBOX = {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

        // Permutation des bits
        public static String permute(String in, int[] table) {
            StringBuilder sb = new StringBuilder(table.length);
            for (int bit : table) sb.append(in.charAt(bit - 1));
            return sb.toString();
        }

        //XOR de deux chaines binaires (0 ou 1) de même longueur
        public static String xor(String a, String b) {
            BigInteger ai = new BigInteger(a, 2), bi = new BigInteger(b, 2);
            String res = ai.xor(bi).toString(2);
            return String.format("%" + a.length() + "s", res).replace(' ', '0');
        }

        //Créer PC2^-1 en mettant "X" depuis K16 (48 bits) pour avoir 56 bits
        public static String revPC2(String k16) {
            char[] k56 = new char[56];
            Arrays.fill(k56, 'x');
            for (int i = 0; i < PC2.length; i++) {
                k56[PC2[i] - 1] = k16.charAt(i);
            }
            return new String(k56);
        }

        //Remplacement des "X" de PC1^-1 et PC2^-1
        public static String replaceUnknownBits(String partial56, int val) {
            String bits = String.format("%8s", Integer.toBinaryString(val & 0xFF))
                               .replace(' ', '0');
            StringBuilder sb = new StringBuilder(partial56);
            int idx = 0;
            for (int i = 0; i < sb.length() && idx < 8; i++) {
                if (sb.charAt(i) == 'x') {
                    sb.setCharAt(i, bits.charAt(idx++));
                }
            }
            return sb.toString();
        }

         //Création de la clé de 64 bits avec bits de parité en mettant "X"
        public static String revPC1(String k56) {
            if (k56.length() != 56) {
                throw new IllegalArgumentException("revPC1 expects 56 bits, got " + k56.length());
            }
            char[] k64 = new char[64];
            Arrays.fill(k64, 'x');
            for (int j = 0; j < PC1.length; j++) {
                k64[PC1[j] - 1] = k56.charAt(j);
            }
            return new String(k64);
        }
    
        /**
         * Ajoute les bits de parité (impairs) :
         * si on reçoit 56 bits, on étend à 64 en laissant 'x' aux parités ;
         * si on reçoit 64 bits (avec 'x' aux parités), on remplace ces 'x' par le bon bit.
         */
        public static String addParityBits(String bits) {
            char[] arr;
            if (bits.length() == 56) {
                arr = new char[64];
                int idx56 = 0;
                for (int i = 0; i < 64; i++) {
                    if ((i + 1) % 8 == 0) {
                        arr[i] = 'x';
                    } else {
                        arr[i] = bits.charAt(idx56++);
                    }
                }
            } else if (bits.length() == 64) {
                arr = bits.toCharArray();
            } else {
                throw new IllegalArgumentException(
                    "addParityBits expects 56 or 64 bits, got " + bits.length());
            }
        
            // Pour chaque octet, on compte les 7 premiers bits et on choisit le 8e
            for (int byteIndex = 0; byteIndex < 8; byteIndex++) {
                int base = byteIndex * 8;
                int sum = 0;
                for (int k = 0; k < 7; k++) {
                    if (arr[base + k] == '1') sum++;
                }
                // si sum est pair, on mets '1' pour que l'octet ait une parité impair
                arr[base + 7] = (sum % 2 == 0) ? '1' : '0';
            }
        
            return new String(arr);
        }

        //Permutation avec IP
        public static String initialPerm(String hex) {
            BigInteger bi = new BigInteger(hex, 16);
            String bin = String.format("%64s", bi.toString(2)).replace(' ', '0');
            return permute(bin, IP);
        }

        //Permutation avec IP^-1
        public static String inverseInitialPerm(String bin64) {
            return permute(bin64, revIP);
        }

        //Séparation en 2 pour les valuers R16 et L16
        public static String[] getR16L16(String cipherHex) {
            String ip = initialPerm(cipherHex);
            // ip[0..31] = R16, ip[32..63] = L16
            String R16 = ip.substring(0, 32);
            String L16 = ip.substring(32);
            return new String[]{ R16, L16 };
        }

        //Expansion de 32 à 48 bits
        public static String expand(String r32) {
            return permute(r32, E);
        }

        //Mettre les 48 bits dans 6 boxes de substitutions
        public static String applySBox(int idx, String six) {
            int row = Integer.parseInt("" + six.charAt(0) + six.charAt(5), 2);
            int col = Integer.parseInt(six.substring(1,5), 2);
            int val = SBOX[idx-1][row][col];
            return String.format("%4s", Integer.toBinaryString(val)).replace(' ','0');
        }
        
        // Inverse de la permutation P (sur 32 bits)
        public static String invertP(String bits32) {
            return permute(bits32, revP);
        }
    }
