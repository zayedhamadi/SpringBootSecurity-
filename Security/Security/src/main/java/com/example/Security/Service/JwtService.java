package com.example.Security.Service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.*;

@Service
public class JwtService {
    private static final String SecretKey = "404E635266556A5886E327237538782F413F4428472B4B6250645367566B5970";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //generat token without extrac claims
    public String generateToken(UserDetails UserDetails) {
        return generateToken(new HashMap<>(), UserDetails);
    }

    //generate a token
    public String generateToken(Map<String, Object> extraClaims, UserDetails UserDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(UserDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))//la date de creer le jwt dans server
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();//function to debut create this all


     }

    public boolean isTokenValid(String token, UserDetails UserDetails) {
        final String username = extractUsername(token);
        return
                (username.equals(UserDetails.getUsername()))
                        && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> ClaimsResolver) {
        final Claims claims = extractAllClaims(token);
        return ClaimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts//begin of crypt jwt
                .parserBuilder()//Le parseur est responsable de décoder et de valider le JWT.
                .setSigningKey(getSignKey())//verifie la signature de jwt
                .build()
                .parseClaimsJwt(token)//le parseur décode le JWT. Il prend le token JWT en tant que paramètre et extrait les informations nécessaires.
                .getBody();//extraire les information qui se trouve dans playload
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
