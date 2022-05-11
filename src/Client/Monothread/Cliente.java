package Client.Monothread;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {
    private static final int PUERTO = 8080;
    private static final String SERVIDOR  = "localhost";
    private static PublicKey pub;
    private static Key simmetricKey;

    private static void communicate(PrintWriter writer, BufferedReader reader) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        writer.println("INICIO");
        if(reader.readLine().equals("ACK")){
            String retoString = crearReto();
            writer.println(retoString);
            byte[] coded_reto = Base64.getDecoder().decode(reader.readLine());
            getPublicKey();
            byte[] reto = decypher(coded_reto, "RSA", pub);
            String reto_decoded = new String(reto);
            if (reto_decoded.equals(retoString)){
                generateKey();
                byte[] llaveCifrada = cypher(simmetricKey.getEncoded(), "RSA", pub);
                writer.println(Base64.getEncoder().encodeToString(llaveCifrada));
                if (reader.readLine().equals("ACK")){
                    byte[] name_coded = cypher("Juan0".getBytes(), "RSA", pub);
                    writer.println(Base64.getEncoder().encodeToString(name_coded));
                    reader.readLine();
                    byte[] idpk_coded = cypher("PedroPabloJuan".getBytes(), "AES", simmetricKey);
                    writer.println(Base64.getEncoder().encodeToString(idpk_coded));
                    byte[] estado_coded = Base64.getDecoder().decode(reader.readLine());
                    writer.println("ACK");
                    String estado_decoded = new String (decypher(estado_coded, "AES", simmetricKey));
                    byte[] hash = Base64.getDecoder().decode(reader.readLine());
                    byte[] hash_comp = getDigest("HmacSHA256", estado_decoded.getBytes());
                    if (Arrays.equals(hash_comp, hash)){
                        System.out.println("Estado del paquete: " + estado_decoded);
                    }else{
                        System.out.println("Error en la consulta");
                    }
                }
            }
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
            e.printStackTrace();
            return null;
        }
        return digest;
    }

    private static byte[] decypher(byte[] coded_texto, String algoritmo, Key key) {
        byte[] texto;
        try{  
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, key);
            texto = cifrador.doFinal(coded_texto);
        }
        catch(Exception e){
            e.printStackTrace();
            System.err.println("Error al descifrar el mensaje.");
            return null;
        }
        return texto;
    }

    private static byte[] cypher(byte[] toBeCyphered, String algorithm, Key key) {
        byte[] llaveCifrada;
        try{
            Cipher cifrador = Cipher.getInstance(algorithm);
            cifrador.init(Cipher.ENCRYPT_MODE, key);
            llaveCifrada = cifrador.doFinal(toBeCyphered);
            return llaveCifrada;
        }catch(Exception e){
            System.err.println("Error al cifrar el mensaje.");
            return null;
        }
    }

    private static void generateKey() throws NoSuchAlgorithmException, IOException {
        KeyGenerator kpg = KeyGenerator.getInstance("AES");
        kpg.init(256);
        simmetricKey = kpg.generateKey();  
    }

    private static void getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        Path path = Paths.get("src/Client/p_key.pub");
        byte[] key = Files.readAllBytes(path);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        pub = kf.generatePublic(spec);

    }

    private static String crearReto(){
        long numero = (long) (Math.random() * 1000000000000L);
        return Long.toString(numero) + Long.toString(numero);
    }
    public static void main(String[] args) throws IOException {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;
        for (int i = 0; i <32; i++){
            try{
                socket = new Socket(SERVIDOR, PUERTO);
                escritor = new PrintWriter(socket.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            }catch(IOException e){
                e.printStackTrace();
                System.exit(-1);
            }
            try{
                communicate(escritor, lector);
            }catch(Exception e){
                e.printStackTrace();
            }
            escritor.close();
            lector.close();
            socket.close();
        }
        
    }
}
