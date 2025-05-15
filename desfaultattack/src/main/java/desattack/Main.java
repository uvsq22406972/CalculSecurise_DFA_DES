package desattack;

public class Main {
    public static void main(String[] args) throws Exception {
        //On récupère K16
        String k16 = DES_K16.recoverK16();
        System.out.println("K16 trouvé : " + k16);
        DESFaultAttack.recoverFullKey(k16);
    }
}
