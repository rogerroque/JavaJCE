package com.company;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        /*Ejercicio1_1();*/
        /*Ejercicio1_2_1();*/
        /*Ejercicio1_2_2();*/
        /*Ejercicio1_3();*/
        /*Ejercicio1_4();*/
        /*Ejercicio1_5();*/
        Ejercicio1_6();
        /*los ejercicios del dos no he sabido*/

    }

    /*Ejercicio 1.1*/
    private static void Ejercicio1_1() throws Exception {

        Scanner scanner = new Scanner(System.in);

        KeyPair keyPair = Metodos.randomGenerate(1024);

        System.out.print("Mensaje a cifrar: ");
        String mensaje = scanner.next();
        byte[] mensajeEnBytes = mensaje.getBytes();

        byte[] mensajeCifrado = Metodos.encryptData(mensajeEnBytes, keyPair.getPublic());
        System.out.print("Mensaje sin decifrar:  ");
        System.out.println(new String(mensajeCifrado));

        byte[] mensajeDescifrado = Metodos.decryptData(mensajeCifrado, keyPair.getPrivate());
        /* Hay un problema y es que cuando imprime el mensaje decifrado solo imprime la primera palabra del mensaje*/
        System.out.print("Mensaje decifrado:  ");
        System.out.println(new String(mensajeDescifrado, StandardCharsets.UTF_8));
    }

    /*Ejercicio 1.2.1*/
    private static void Ejercicio1_2_1() throws Exception {

        KeyStore keystore = Metodos.loadKeyStore("D:\\Descargas\\myKeystore.keystore", "usuario");
        System.out.println("Type: " + keystore.getType());
        System.out.println("Size: " + keystore.size());
        System.out.println("Aliases: " + keystore.aliases());
        System.out.println("Cert: " + keystore.getCertificate("21Roger"));
        System.out.println("Algoritme: " + keystore.hashCode());

    }

    /*Ejercicio 1.2.1*/
    private static void Ejercicio1_2_2() throws Exception {
        KeyStore keystore = Metodos.loadKeyStore("D:\\Descargas\\myKeystore.keystore", "usuario");
        SecretKey sKey = Metodos.keygenKeyGeneration(128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(sKey);
        String password = "usuario";
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
        keystore.setEntry("21Roger", secretKeyEntry, protectionParameter);

        System.out.println(keystore.isKeyEntry("21Roger"));
    }

    /*Ejercicio 1.3*/
    private static void Ejercicio1_3() throws Exception {

        File certificado = new File("D:\\Descargas\\jordi.cer");
        System.out.println(Metodos.getPublicKey(certificado));
    }

    /*Ejercicio 1.4*/
    private static void Ejercicio1_4() throws Exception {

        KeyStore keystore = Metodos.loadKeyStore("D:\\Descargas\\myKeystore.keystore", "usuario");
        System.out.println(Metodos.getPublicKeyE4(keystore, "21Teemo", "usuario"));
    }

    /*Ejercicio 1.5*/
    private static void Ejercicio1_5() {
        KeyPair keyPair = Metodos.randomGenerate(1024);
        byte[] sign = Metodos.signData("Mensaje".getBytes(), keyPair.getPrivate());
        System.out.println(new String(sign));
    }

    /*Ejercicio 1.6*/
    private static void Ejercicio1_6() {
        KeyPair keyPair = Metodos.randomGenerate(1024);
        byte[] text = "Mensaje".getBytes();
        byte[] sign = Metodos.signData(text, keyPair.getPrivate());
        boolean validated = Metodos.validateSignature(text, sign, keyPair.getPublic());
        System.out.println(validated);
    }

}

