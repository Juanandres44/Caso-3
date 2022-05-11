package Server.Monothread;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import Server.Estado;

public class Servidor{
    private static HashMap<String, HashMap<String, Estado>> paquetes;
    private static ServerSocket socket;
    private static final int PUERTO = 8080;
    private static KeyPair keyPair;
    private static Key simmetricKey;
    private static Key simmetricKey2;
    
    private static void listen(PrintWriter writer, BufferedReader reader) throws IOException {
        String inputLine;
        String reto;
        inputLine = reader.readLine();
        if (inputLine.equals("INICIO")){
            writer.println("ACK");
            reto = reader.readLine();
            long tiempoInicial = System.nanoTime();
            byte[] coded_reto = cypher(reto, "RSA", keyPair.getPrivate());
            long tiempoFinal = System.nanoTime();
            System.out.println("Tiempo de cifrado con llave asimetrica: " + (tiempoFinal - tiempoInicial));
            tiempoInicial = System.nanoTime();
            cypher(reto, "AES", simmetricKey2);
            tiempoFinal = System.nanoTime();
            System.out.println("Tiempo de cifrado con llave simetrica: " + (tiempoFinal - tiempoInicial));
            writer.println(Base64.getEncoder().encodeToString(coded_reto));
            byte[] llave_simetrica = Base64.getDecoder().decode(reader.readLine());
            simmetricKey = new SecretKeySpec(decypher(llave_simetrica, "RSA", (Key) keyPair.getPrivate()), "AES");
            writer.println("ACK");
            byte[] name = Base64.getDecoder().decode(reader.readLine());
            String decoded_name = new String(decypher(name, "RSA", (Key) keyPair.getPrivate()));
            if (paquetes.get(decoded_name) != null){
                writer.println("ACK");
            }else{
                writer.println("ERROR");
            }
            byte[] idpk = Base64.getDecoder().decode(reader.readLine());
            byte[] idpk_decoded = decypher(idpk, "AES", simmetricKey);
            String estado_string;
            if (paquetes.get(decoded_name) != null){
                Estado estado = paquetes.get(decoded_name).get(new String(idpk_decoded));
                if ((estado)!= null){
                    estado_string = estado.toString();
                }else{
                    estado_string = "DESCONOCIDO";
                }
            }else{
                estado_string = "DESCONOCIDO";
            }
            byte[] estado_coded = cypher(estado_string, "AES", simmetricKey);
            writer.println(Base64.getEncoder().encodeToString(estado_coded));
            reader.readLine();
            byte[] mensaje = getDigest("HmacSHA256", estado_string.getBytes());
            writer.println(Base64.getEncoder().encodeToString(mensaje));
        }else{
            System.err.println("No se pudo establecer una conexión segura.");
        }
    }

    private static byte[] getDigest(String algoritmo, byte[] mensaje){
        byte [] digest;
        try{
            Mac mac = Mac.getInstance(algoritmo);
            SecretKeySpec secretKeySpec = new SecretKeySpec(simmetricKey.getEncoded(), algoritmo);
            mac.init(secretKeySpec);
            digest = mac.doFinal(mensaje);
        }catch(Exception e){
            e.printStackTrace();;
            return null;
        }
        return digest;
    }

    private static byte[] decypher(byte[] coded_text, String algoritmo, Key key) {
        byte[] decoded_text;
        try{
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, key);
            decoded_text = cifrador.doFinal(coded_text);
            return decoded_text;
        }
        catch(Exception e){
            e.printStackTrace();
            System.err.println("Error al descifrar la llave.");
            return null;
        }
    }

    private static byte[] cypher(String texto, String algoritmo, Key key) {
        byte[] textoCifrado;
        try{
            Cipher cifrador = Cipher.getInstance(algoritmo);
            byte[] textoB = texto.getBytes();
            cifrador.init(Cipher.ENCRYPT_MODE, key);
            textoCifrado = cifrador.doFinal(textoB);
            return textoCifrado;
        }catch(Exception e){
            System.err.println("Error al cifrar el mensaje.");
            return null;
        }
    }

    private static void generateKey() throws NoSuchAlgorithmException, IOException {
        KeyGenerator kpg = KeyGenerator.getInstance("AES");
        kpg.init(256);
        simmetricKey2 = kpg.generateKey();  
    }

    private static void generateKeys() throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        keyPair = kpg.generateKeyPair();
        FileOutputStream file =  new FileOutputStream("src/Client/p_key.pub");
        file.write(keyPair.getPublic().getEncoded());
        file.close();
        generateKey();
    }

    private static void fillPaquetes(){
        paquetes = new HashMap<String, HashMap<String, Estado>>();
        for (Integer i = 0; i < 32; i++){
            paquetes.put("Juan"+i, new HashMap<String, Estado>());
            paquetes.get("Juan"+i).put("PedroPabloJuan", Estado.PKT_EN_OFICINA);
        }
    }
    public static void main(String[] args) {
        try{
            Servidor.generateKeys();
        }catch(Exception e){
            System.err.println("No se pudo generar las claves.");
            System.exit(-1);
        }
        
        socket = null;
        boolean online = true;
        fillPaquetes();
        try{
            socket = new ServerSocket(PUERTO);
            while (online){
                Socket ss = socket.accept();
                PrintWriter writer = new PrintWriter(ss.getOutputStream(), true);
                BufferedReader reader = new BufferedReader(new InputStreamReader(ss.getInputStream()));
                try{
                    Servidor.listen(writer, reader);
                }catch(Exception e){
                    e.printStackTrace();
                }
                writer.close();
                reader.close();
                ss.close();
            }
        }catch(IOException e){
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
