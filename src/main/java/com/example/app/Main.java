package com.example.app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.json.Json;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;


public class Main {

    public static void main(String[] args) throws FileNotFoundException, IOException {

        Gson gson = new Gson();
        if(args.length>0){
            Map properties = gson.fromJson(new FileReader(args[0]), Map.class);
            String aud = (String) properties.get("client_email");
            if(args.length > 1) {
                aud = args[1] ;
            }

            Date now = new Date();
            Date expTime = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(3600));
            // Build the JWT payload
            JWTCreator.Builder token = JWT.create()
                    .withIssuedAt(now)
                    // Expires after 'expiraryLength' seconds
                    .withExpiresAt(expTime)
                    // Must match 'issuer' in the security configuration in your
                    // swagger spec (e.g. service account email)
                    .withIssuer(properties.get("client_email").toString())
                    // Must be either your Endpoints service name, or match the value
                    // specified as the 'x-google-audience' in the OpenAPI document
                    .withAudience(aud)
                    //.withAudience(properties.get("client_email").toString())
                    // Subject and email should match the service account's email
                    .withSubject(properties.get("client_email").toString())
                    .withClaim("email", properties.get("client_email").toString());

            // Sign the JWT with a service account
            FileInputStream stream = new FileInputStream(args[0]);
            GoogleCredential cred = GoogleCredential.fromStream(stream);
            RSAPrivateKey key = (RSAPrivateKey) cred.getServiceAccountPrivateKey();
            Algorithm algorithm = Algorithm.RSA256(null, key);
            System.out.println(properties.get("client_email").toString()+"\n"+token.sign(algorithm)+"\n");
            
        }
    }

}