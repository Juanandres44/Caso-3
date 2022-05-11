package Server.Multithread;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import Server.Estado;
public class Server {

    private static KeyPair keyPair;
    private static ServerSocket socket;
    private static final int PUERTO = 8080;
    private static HashMap<String, HashMap<String, Estado>> paquetes;

    private static void generateKeys() throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        keyPair = kpg.generateKeyPair();
        FileOutputStream file =  new FileOutputStream("src/Client/p_key.pub");
        file.write(keyPair.getPublic().getEncoded());
        file.close();
    }

    private static void fillPaquetes(){
        paquetes = new HashMap<String, HashMap<String, Estado>>();
        for (Integer i = 0; i < 32; i++){
            paquetes.put("Juan"+i, new HashMap<String, Estado>());
            paquetes.get("Juan"+i).put("PedroPabloJuan", Estado.PKT_EN_OFICINA);
        }
    }

    public static void main(String[] args) {
        socket = null;
        fillPaquetes();
        try {
            generateKeys();
            socket = new ServerSocket(PUERTO);
            socket.setReuseAddress(true);
            while(true){
                Socket client = socket.accept();
                new ClientHandler(client, keyPair, paquetes).start();
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }finally{
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
