package Server.Multithread;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import Server.Estado;

public class ClientHandler extends Thread{

    private Socket socket;
    private KeyPair keyPair;
    private HashMap<String, HashMap<String, Estado>> paquetes;
    private Key simmetricKey;
    private Key simmetricKey2;

    public ClientHandler(Socket client, KeyPair keyPair, HashMap<String, HashMap<String, Estado>> paquetes) {
        this.socket = client;
        this.keyPair = keyPair;
        this.paquetes = paquetes;
    }

    private void listen(PrintWriter writer, BufferedReader reader) throws IOException {
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
            writer.write(Base64.getEncoder().encodeToString(mensaje));
        }else{
            System.err.println("No se pudo establecer una conexi??n segura.");
        }
    }

    private byte[] getDigest(String algoritmo, byte[] mensaje){
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

    private byte[] decypher(byte[] coded_text, String algoritmo, Key key) {
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

    private byte[] cypher(String texto, String algoritmo, Key key) {
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

    private void generateKey() throws NoSuchAlgorithmException, IOException {
        KeyGenerator kpg = KeyGenerator.getInstance("AES");
        kpg.init(256);
        simmetricKey2 = kpg.generateKey();  
    }

    public void run(){
        try{
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            try{
                generateKey();
                listen(writer, reader);
            }catch(Exception e){
                e.printStackTrace();
            }
            writer.close();
            reader.close();
            socket.close();
            
        }catch(IOException e){
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
