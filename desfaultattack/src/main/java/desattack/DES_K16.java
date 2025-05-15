package desattack;

import java.util.*;

    /**
     * Récupération automatique de K16 (48 bits) sur le dernier tour.
     */
    public class DES_K16 {
        /**
         * Analyser et récupérer la faute sur le dernier tour.
         */
        public static String recoverK16() {
            String corrHex = DESGeneralFunctions.CIPHER_CORR_HEX;
            //Récupère R16 et L16 du texte clair correct après IP
            String[] halvesCorr = DESGeneralFunctions.getR16L16(corrHex);
            String R16corr = halvesCorr[0];
            String L16corr = halvesCorr[1];

            //Pour chaque S-box, on conserve une liste de sets de candidats
            List<List<Set<String>>> allCandidates = new ArrayList<>(8);
            for (int i = 0; i < 8; i++) {
                allCandidates.add(new ArrayList<>());
            }

            //Itère sur tous les texts chiffrés faux
            for (long fCtxt : DESGeneralFunctions.CIPHER_FAULTY_HEX) {
                String faultHex = String.format("%016X", fCtxt);
                // Récupère R16 et L16 du faulty
                String[] halvesF = DESGeneralFunctions.getR16L16(faultHex);
                String R16f = halvesF[0];
                String L16f = halvesF[1];

                // ΔR16 puis ΔS = revP(ΔR16)
                String deltaR = DESGeneralFunctions.xor(R16corr, R16f);
                String deltaS = DESGeneralFunctions.invertP(deltaR);

                // Expansion de R15 = L16 avant dernier tour
                String eR   = DESGeneralFunctions.expand(L16corr);
                String eRf  = DESGeneralFunctions.expand(L16f);

                // Pour chaque S-box, bruteforce si eq4 != "0000"
                for (int box = 0; box < 8; box++) {
                    String eq4 = deltaS.substring(box * 4, box * 4 + 4);
                    if ("0000".equals(eq4)) continue;
                    String r6   = eR.substring(box * 6, box * 6 + 6);
                    String r6f  = eRf.substring(box * 6, box * 6 + 6);

                    Set<String> local = new HashSet<>();
                    for (int k = 0; k < 64; k++) {
                        String kbits = String.format("%6s", Integer.toBinaryString(k)).replace(' ', '0');
                        String s1 = DESGeneralFunctions.applySBox(box + 1, DESGeneralFunctions.xor(r6, kbits));
                        String s2 = DESGeneralFunctions.applySBox(box + 1, DESGeneralFunctions.xor(r6f, kbits));
                        if (DESGeneralFunctions.xor(s1, s2).equals(eq4)) {
                            local.add(kbits);
                        }
                    }
                    if (!local.isEmpty()) {
                        allCandidates.get(box).add(local);
                    }
                }
            }

            //Intersection finale et construction de K16
            StringBuilder k16 = new StringBuilder(48);
            for (int box = 0; box < 8; box++) {
                List<Set<String>> lists = allCandidates.get(box);
                if (lists.isEmpty()) {
                    throw new IllegalStateException("Pas assez d'information pour S" + (box + 1));
                }
                Set<String> inter = new HashSet<>(lists.get(0));
                for (int i = 1; i < lists.size(); i++) {
                    inter.retainAll(lists.get(i));
                }
                if (inter.isEmpty()) {
                    throw new IllegalStateException("Aucun candidat commun pour S" + (box + 1));
                }
                List<String> sorted = new ArrayList<>(inter);
                Collections.sort(sorted);
                k16.append(sorted.get(0));
            }
            return k16.toString();
        }
    }
