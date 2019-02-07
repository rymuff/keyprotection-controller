package com.kweisa.controller;

import javax.bluetooth.DiscoveryAgent;
import javax.bluetooth.LocalDevice;
import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnection;
import javax.microedition.io.StreamConnectionNotifier;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class Controller {
    private static final String SERVER_UUID = "0000110100001000800000805F9B34FB";
    private static final String SERVER_URL = "btspp://localhost:" + SERVER_UUID + ";name=Controller";

    public static void main(String[] args) throws IOException, InterruptedException {
        LocalDevice.getLocalDevice().setDiscoverable(DiscoveryAgent.GIAC);
        StreamConnectionNotifier streamConnectionNotifier = (StreamConnectionNotifier) Connector.open(SERVER_URL);

        int count = 0;
        ServerThread serverThread = null;

        while (count < 5) {
            StreamConnection streamConnection = streamConnectionNotifier.acceptAndOpen();
            serverThread = new ServerThread(streamConnection);
            serverThread.start();
            System.out.println(++count);
        }

        serverThread.wait();
        streamConnectionNotifier.close();
    }

    static class ServerThread extends Thread {
        StreamConnection streamConnection;
        BufferedReader bufferedReader;
        BufferedWriter bufferedWriter;

        ServerThread(StreamConnection streamConnection) {
            this.streamConnection = streamConnection;
        }

        void send(byte[] data) throws IOException {
            String message = Base64.getEncoder().encodeToString(data);

            bufferedWriter.write(message + "\n");
            bufferedWriter.flush();

            System.out.printf("[>] %s\n", message);
        }

        byte[] receive() throws IOException {
            String message = bufferedReader.readLine();
            System.out.printf("[<] %s\n", message);

            return Base64.getDecoder().decode(message);
        }

        @Override
        public void run() {
            try {
                bufferedReader = new BufferedReader(new InputStreamReader(streamConnection.openInputStream()));
                bufferedWriter = new BufferedWriter(new OutputStreamWriter(streamConnection.openOutputStream()));

                // Receive Certificate
                byte[] certificateBytes = receive();
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));

                // Generate nonce
                byte[] nonce = new byte[32];
                SecureRandom secureRandom = SecureRandom.getInstanceStrong();
                secureRandom.nextBytes(nonce);

                // Send nonce
                send(nonce);

                // Receive signature
                byte[] sign = receive();

                // Verify signature
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(certificate.getPublicKey());
                signature.update(nonce);

                System.out.println("[*] Verify result: " + signature.verify(sign));

                close();
            } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }
        }

        void close() throws IOException {
            bufferedReader.close();
            bufferedWriter.close();
            streamConnection.close();
        }
    }
}
