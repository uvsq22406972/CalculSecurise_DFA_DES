package desattack;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.IntStream;
import static org.junit.jupiter.api.Assertions.*;

class DESFaultAttackTest {

    @Test
    void testXor_basic() {
        // 1010 xor 0101 = 1111
        String a = "1010";
        String b = "0101";
        String expected = "1111";
        assertEquals(expected, DESGeneralFunctions.xor(a, b));
    }

    @Test
    void testPermuteAndInversePermute() {
        // On génère un mot binaire 64 bits à partir d'un hex fixe
        String hex = "0123456789ABCDEF";
        BigInteger bi = new BigInteger(hex, 16);
        String bin64 = String.format("%64s", bi.toString(2)).replace(' ', '0');

        // Permutation initiale puis inverse
        String afterIP = DESGeneralFunctions.permute(bin64, DESGeneralFunctions.IP);
        String afterInv = DESGeneralFunctions.permute(afterIP, DESGeneralFunctions.revIP);

        assertEquals(bin64, afterInv,
            "L'inversion de IP via revIP doit redonner le binaire initial");
    }

    @Test
    void testAddParityBits_lengthAndParity() {
        // on construit une clé partielle 56 bits aléatoire '0' ou '1'
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 56; i++) {
            sb.append((i % 2 == 0) ? '1' : '0');
        }
        String partial56 = sb.toString();
        String withParity = DESGeneralFunctions.addParityBits(partial56);

        // Doit faire 64 bits
        assertEquals(64, withParity.length());

        // Vérifier que chaque octet a une parité impaire
        for (int byteIndex = 0; byteIndex < 8; byteIndex++) {
            String octet = withParity.substring(byteIndex * 8, byteIndex * 8 + 8);
            long ones = octet.chars().filter(ch -> ch == '1').count();
            assertTrue(ones % 2 == 1,
                "Octet #" + byteIndex + " doit avoir un nombre impair de bits à 1");
        }
    }

    @Test
    void testInitialPerm_extractsR16L16() {
        // Pour un cipher fixe on vérifie L16/R16 retournés non nuls
        String cipherHex = DESGeneralFunctions.CIPHER_CORR_HEX;
        String[] halves = DESGeneralFunctions.getR16L16(cipherHex);

        assertEquals(2, halves.length);
        assertEquals(32, halves[0].length(), "R16 doit faire 32 bits");
        assertEquals(32, halves[1].length(), "L16 doit faire 32 bits");
    }

    @Test
    void testRevPC2Mapping() {
        // Build a 48-char string: 'A','B',... upto 'A'+47
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 48; i++) sb.append((char)('A' + i));
        String k16 = sb.toString();

        String k56 = DESGeneralFunctions.revPC2(k16);
        assertEquals(56, k56.length(), "revPC2 doit renvoyer 56 caractères");

        // Vérifier le placement correct des 48 bits
        for (int i = 0; i < 48; i++) {
            int pos = DESGeneralFunctions.PC2[i] - 1;
            assertEquals(k16.charAt(i), k56.charAt(pos),
                "Le caractère à l'index " + i + " doit être placé à la position " + pos);
        }
        // Vérifier que les autres positions sont 'x'
        IntStream.range(0,56)
            .filter(idx -> Arrays.stream(DESGeneralFunctions.PC2).noneMatch(p -> p-1 == idx))
            .forEach(idx -> assertEquals('x', k56.charAt(idx),
                "Position " + idx + " doit être 'x'"));
    }

    @Test
    void testReplaceUnknownBits() {
        String partial56 = String.join("", Collections.nCopies(56, "x"));
        int pattern = 0b10101010;
        String filled = DESGeneralFunctions.replaceUnknownBits(partial56, pattern);
        assertEquals(56, filled.length(), "La longueur doit rester 56");
        // Les 8 premiers 'x' sont remplacés
        String expectedPrefix = String.format("%8s", Integer.toBinaryString(pattern))
                                    .replace(' ', '0');
        assertTrue(filled.startsWith(expectedPrefix),
            "Les 8 premiers bits doivent correspondre à la valeur binaire de pattern");
        // Il reste 48 'x'
        long xs = filled.chars().filter(ch -> ch == 'x').count();
        assertEquals(48, xs, "Il doit rester 48 'x' après le remplacement");
    }

    @Test
    void testRevPC1Mapping() {
        // 56-bit sample: repeating digits 0-9
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 56; i++) sb.append((char)('0' + (i % 10)));
        String k56 = sb.toString();

        String k64woPar = DESGeneralFunctions.revPC1(k56);
        assertEquals(64, k64woPar.length(), "revPC1 doit renvoyer 64 caractères");

        // Vérifier le placement des 56 bits
        for (int j = 0; j < DESGeneralFunctions.PC1.length; j++) {
            int pos = DESGeneralFunctions.PC1[j] - 1;
            assertEquals(k56.charAt(j), k64woPar.charAt(pos),
                "Le bit 56-bit index " + j + " doit aller à la position " + pos);
        }
        // Les positions non PC1 doivent être 'x'
        IntStream.range(0,64)
            .filter(idx -> Arrays.stream(DESGeneralFunctions.PC1).noneMatch(p -> p-1 == idx))
            .forEach(idx -> assertEquals('x', k64woPar.charAt(idx),
                "Position de parité " + idx + " doit être 'x'"));
    }

    @Test
    void testAddParityBitsParities() {
        // Génère un k56 puis apply revPC1 pour obtenir 64 bits sans parité
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 56; i++) sb.append((i % 2 == 0) ? '1' : '0');
        String k56 = sb.toString();
        String k64woPar = DESGeneralFunctions.revPC1(k56);

        String k64 = DESGeneralFunctions.addParityBits(k64woPar);
        assertEquals(64, k64.length(), "addParityBits doit renvoyer 64 bits");

        // Chaque octet doit avoir une parité impair
        for (int i = 0; i < 8; i++) {
            String octet = k64.substring(i*8, i*8+8);
            long ones = octet.chars().filter(ch -> ch == '1').count();
            assertTrue(ones % 2 == 1, "Octet " + i + " doit avoir une parité impair");
        }
    }

    @Test
    void testApplySBox_knownValue() {
        // Pour S1, entrée "000000" => row=0,col=0 => valeur=14 => "1110"
        String in = "000000";
        String out = DESGeneralFunctions.applySBox(1, in);
        assertEquals("1110", out, "applySBox doit produire 1110 pour S1 et entrée 000000");
    }

    @Test
    void testExpand_allZeros() {
        String zeros32 = String.join("", Collections.nCopies(32, "0"));
        String exp = DESGeneralFunctions.expand(zeros32);
        assertEquals(48, exp.length(), "expand doit renvoyer 48 bits");
        assertTrue(exp.chars().allMatch(ch -> ch == '0'), "expand de zeros doit rester zeros");
    }

    @Test
    void testSplitPAndInverseP() {
        // Génère un mot aléatoire de 32 bits
        String rand32 = "10110011100011110000111100001111";
        String permuted = DESGeneralFunctions.permute(rand32, DESGeneralFunctions.P);
        String inv = DESGeneralFunctions.invertP(permuted);
        assertEquals(rand32, inv, "invertP doit inverser la permutation P");
    }

    @Test
    void testRecoverK16_correctValue() {
        String found = DES_K16.recoverK16();
        String expected = "001100100101001110101000010000111010001010010110";
        assertEquals(expected, found, "recoverK16 doit renvoyer la sous-clé correcte");
    }

    @Test
    void testRecoverFullKey_outputsExpected() throws Exception {
        String k16 = DES_K16.recoverK16();
        // Capture System.out
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(baos));

        DESFaultAttack.recoverFullKey(k16);

        System.out.flush();
        System.setOut(oldOut);
        String output = baos.toString();

        assertTrue(output.contains("Clé trouvée"), "recoverFullKey doit afficher Clé trouvée");
        assertTrue(output.toUpperCase().contains("6B0EA702C4D55702"),
            "recoverFullKey doit trouver la clé complète 6B0EA702C4D55702");
    }

    @Test
    void testSBoxKnownValues() {
        // Standard DES test vectors
        assertEquals("0101", DESGeneralFunctions.applySBox(1, "011011")); // S1
        assertEquals("1011", DESGeneralFunctions.applySBox(2, "100110")); // S2
        assertEquals("1111", DESGeneralFunctions.applySBox(3, "101010")); // S3
        assertEquals("1001", DESGeneralFunctions.applySBox(4, "001100")); // S4
    }

    @Test
    void testExpand() {
        String r32 = "11110000101010101111000010101010";
        String expanded = DESGeneralFunctions.expand(r32);
        // Known expansion of above input
        assertEquals("011110100001010101010101011110100001010101010101", expanded);
    }

    @Test
    void testExpansion() {
        String input = "11110000101010101111000010101010";
        String expected = "011110100001010101010101011110100001010101010101";
        assertEquals(expected, DESGeneralFunctions.expand(input));
    }

    @Test 
    void testInverseP() {
        String input = "01010101010101010101010101010101";
        String permuted = DESGeneralFunctions.permute(input, DESGeneralFunctions.P);
        String inverted = DESGeneralFunctions.invertP(permuted);
        assertEquals(input, inverted);
    }
}
