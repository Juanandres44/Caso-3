package Client.Multithread;

import java.util.Scanner;

public class ClientCreator {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Digite el número de clientes que desea crear: ");
        int numeroClientes = sc.nextInt();
        sc.close();
        for (int i = 0; i < numeroClientes; i++) {
            new MiniClient().start();
        }
    }
}
