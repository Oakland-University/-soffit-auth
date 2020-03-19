package edu.oakland.soffit.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
  @Value("${org.apereo.portal.soffit.jwt.encryptionPassword:CHANGEME}")
  private String ENCRYPTION_PASSWORD;

  @Value("${org.apereo.portal.soffit.jwt.signatureKey:CHANGEME}")
  private String SIGNATURE_KEY;

  @Value("${org.apereo.portal.soffit.jwt.issuer}")
  private String ISSUER;

  @Value("${edu.oakland.soffit.parser.strict:true}")
  private boolean strictMode;

  @Value("${org.apereo.portal.soffit.jwt.algorithm:null}")
  private String algorithm;

  private Algorithm SIGNING_ALGORITHM;

  private BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
  private byte[] b;
  private JWTVerifier verifier;

  @PostConstruct
  protected void init() {
    b = javax.xml.bind.DatatypeConverter.parseBase64Binary(SIGNATURE_KEY);
    textEncryptor.setPassword(ENCRYPTION_PASSWORD);

    switch (algorithm) {
      case "HS256":
        SIGNING_ALGORITHM = Algorithm.HMAC256(b);
        break;
      case "HS384":
        SIGNING_ALGORITHM = Algorithm.HMAC384(b);
        break;
      case "HS512":
        SIGNING_ALGORITHM = Algorithm.HMAC512(b);
        break;
      default:
        SIGNING_ALGORITHM = Algorithm.HMAC512(b);
        break;
    }

    verifier =
        JWT.require(SIGNING_ALGORITHM).withIssuer(ISSUER).build(); // Reusable verifier instance
  }

  /**
   * This method returns the Bearer token from an HttpServletRequest's Authorization header
   *
   * <p>This library expects JWTs to be passed as bearer tokens via the Authorization header. This
   * header has the form: <code>"authorization", "Bearer some-token"</code> The method first
   * attempts to grab the value of the header, and return the contents of the string after the first
   * space. Else it throws an exception
   *
   * @param request - an HttpServletRequest contianing a JWT/E bearer token
   * @throws SoffitAuthException - If a request doesn't have an AUTHORIZATION header
   * @return String - a JWT
   */
  public String getBearerToken(HttpServletRequest request) throws SoffitAuthException {
    try {
      // getHeader method is case insensitive - no capital 'A' is necessary
      String header = request.getHeader("authorization");
      if (header.isEmpty()) {
        throw new SoffitAuthException("Authorization header not included in request", null);
      }
      return header.split(" ")[1];
    } catch (PatternSyntaxException | ArrayIndexOutOfBoundsException | NullPointerException e) {
      throw new SoffitAuthException("Token not provided with authorization header", e);
    }
  }

  /**
   * This method takes a token string and tries to determine which algorithm to use in the
   * authorizer's verification attempt.
   *
   * <p>Currently the supported algorithms are HMAC 256, 384, and 512. Although auth0 provides
   * support for many more algorithms, this library does not, since uPortal does not.
   *
   * <p>The default signing algorithm is the same as uPortal's - HMAC512
   *
   * @param token - a JWT String
   * @throws SoffitAuthException - if an unsupported signing algorithm is provided
   * @return Algorithm - auth0 provided signing algorithm
   */
  public Algorithm determineAlgorithm(String token) throws SoffitAuthException {
    DecodedJWT unverified;
    try {
      unverified = JWT.decode(token);
    } catch (JWTDecodeException e) {
      throw new SoffitAuthException("Given token is not a valid JWT: " + token, e);
    }

    switch (unverified.getAlgorithm()) {
      case "HS256":
        return Algorithm.HMAC256(b);
      case "HS384":
        return Algorithm.HMAC384(b);
      case "HS512":
        return Algorithm.HMAC512(b);
      default:
        throw new SoffitAuthException(
            "Unsupported signing algorithm: "
                + unverified.getAlgorithm()
                + ". \nCurrently only HS256, HS384, and HS512 are supported ",
            null);
    }
  }

  /**
   * This method attempts to verify the legitimacy of a JWT
   *
   * <p>The AuthService member variable `strictMode` is used here to determine if the verification
   * algorithm should be auto-determined or use the one the user provided in their
   * application.properties file.
   *
   * <p>Most exceptions that usually come up are thrown in this method. For more information about
   * each exception type and why they typically occur, see the documentation for SoffitAuthException
   * {@link SoffitAuthException}
   *
   * @param token - JWT String to verify
   * @throws SoffitAuthException - if verification fails at any step. See above docs for more info
   * @return DecodedJWT - auth0 Object representing a verified JWT
   */
  public DecodedJWT verifyToken(String token) throws SoffitAuthException {
    try {
      // StrictMode determines if the algorithm should be determined from
      // the JWT header or the application.properties file
      if (strictMode) {
        return verifier.verify(token);
      }

      JWTVerifier second = JWT.require(determineAlgorithm(token)).withIssuer(ISSUER).build();
      return second.verify(token);
    } catch (SignatureVerificationException e) {
      throw new SoffitAuthException("Failed to verify token:\n" + token, e);
    } catch (InvalidClaimException e) {
      DecodedJWT jwt = JWT.decode(token);
      throw new SoffitAuthException(
          "Incorrect claim. Probably an issuer mismatch.\nGiven ISSUER: \t"
              + ISSUER
              + "\nJWT's iss:\t"
              + jwt.getIssuer()
              + "\nComplete token: "
              + token,
          e);
    } catch (TokenExpiredException e) {
      throw new SoffitAuthException("Provided token is past expiration date.", e);
    } catch (Exception e) {
      // Some unforseen exception occurred. See 'e' for more info
      throw new SoffitAuthException("Unknown Exception Occurred", e);
    }
  }

  /**
   * This method attempts to decrypt a JWE
   *
   * <p>This method uses Jasypt's BasicTextEncryptor class to decrypt a JWE. In the future, more
   * standard encryption libraries may be used, but uPortal's soffit library only supports the
   * StandardPBEStringEncryptor at this time
   *
   * @param jwe - JWE String to decrypt
   * @throws SoffitAuthException - if decryption failed for any reason
   * @return decryptedJWT - valid jwt string
   */
  public String decryptToken(String jwe) throws SoffitAuthException {
    try {
      return textEncryptor.decrypt(jwe);
    } catch (EncryptionInitializationException | EncryptionOperationNotPossibleException e) {
      String error =
          "Decryption of JWE failed. JWE in question: "
              + jwe
              + "\nCurrently this library only supports encryption operations with jasypt's BasicTextEncryptor.";
      throw new SoffitAuthException(error, e);
    }
  }

  /**
   * This method attempts to get a specified claim from a request's Authorization header
   *
   * <p>This method will be the primary method used by Soffits pre uPortal 5.7.1, since all tokens
   * are encrypted in earlier versions. The bearer token must be present in the request passed to
   * this method, or an exception will be thrown. If the claim is not found, `null` will be returned
   *
   * @param request - HttpServletRequest with JWE Bearer token
   * @param claimName - String key for the desired claim
   * @throws SoffitAuthException - if decryption/verification fails at any point
   * @return Claim - auth0 Claim object
   */
  public Claim getClaimFromJWE(HttpServletRequest request, String claimName)
      throws SoffitAuthException {
    String jwe = getBearerToken(request);
    String jwt = decryptToken(jwe);
    DecodedJWT decoded = verifyToken(jwt);

    return decoded.getClaim(claimName);
  }

  /**
   * This method is attempts to return a map of all claims in a JWE
   *
   * <p>This is primarily a convenience method for developers - very rarely will a soffit need
   * anything other than a unique identifier and perhaps group membership information. This method
   * was created with the intention of letting developers see what is contained inside of a JWE in a
   * convenient way.
   *
   * @param request - HttpServletRequest with JWE Bearer token
   * @throws SoffitAuthException - if decryption/verification fails at any point
   * @return Claim - auth0 Claim object
   */
  public Map<String, Claim> getClaimsFromJWE(HttpServletRequest request)
      throws SoffitAuthException {
    String jwe = getBearerToken(request);
    String jwt = decryptToken(jwe);
    DecodedJWT decoded = verifyToken(jwt);

    return decoded.getClaims();
  }

  /**
   * This method is attempts to return a map of specific claims from a JWE
   *
   * <p>For cases where more than one claim is needed, this method will return a <code>
   * Map<String, Claim></code> containing just the keys which you've specified in the claimNames var
   * args parameter.
   *
   * <p>If a given key name does not exist in the decoded JWT, then the value provided in the
   * returned map will be <code>null</code>
   *
   * @param request - HttpServletRequest with JWE Bearer token
   * @param claimNames - A variable number of claimNames to be included in the returned map
   * @throws SoffitAuthException - if decryption/verification fails at any point
   * @return Map<String, Claim> - a map of desired Claims with String keys
   */
  public Map<String, Claim> getClaimsFromJWE(HttpServletRequest request, String... claimNames)
      throws SoffitAuthException {
    String jwe = getBearerToken(request);
    String jwt = decryptToken(jwe);
    DecodedJWT decoded = verifyToken(jwt);
    Map<String, Claim> allClaims = decoded.getClaims();

    Map<String, Claim> userMap = new HashMap<>();

    for (String claimName : claimNames) {
      userMap.put(claimName, allClaims.get(claimName));
    }

    return userMap;
  }

  /**
   * This method attempts to get a specified claim from a request's Authorization header
   *
   * <p>The bearer token must be present in the request passed to this method, or an exception will
   * be thrown. If the claim is not found, `null` will be returned
   *
   * @param request - HttpServletRequest with JWE Bearer token
   * @param claimName - String key for the desired claim
   * @throws SoffitAuthException - if decryption/verification fails at any point
   * @return Claim - auth0 Claim object
   */
  public Claim getClaimFromJWT(HttpServletRequest request, String claimName)
      throws SoffitAuthException {
    String jwt = getBearerToken(request);
    DecodedJWT decoded = verifyToken(jwt);

    return decoded.getClaim(claimName);
  }

  /**
   * This method is attempts to return a map of all claims in a JWT
   *
   * <p>This is primarily a convenience method for developers - very rarely will a soffit need
   * anything other than a unique identifier and perhaps group membership information. This method
   * was created with the intention of letting developers see what is contained inside of a JWT in a
   * convenient way.
   *
   * @param request - HttpServletRequest with JWE Bearer token
   * @throws SoffitAuthException - if decryption/verification fails at any point
   * @return Claim - auth0 Claim object
   */
  public Map<String, Claim> getClaimsFromJWT(HttpServletRequest request)
      throws SoffitAuthException {
    String jwt = getBearerToken(request);
    DecodedJWT decoded = verifyToken(jwt);

    return decoded.getClaims();
  }

  /**
   * This method is attempts to return a map of specific claims from a JWT
   *
   * <p>For cases where more than one claim is needed, this method will return a <code>
   * Map<String, Claim></code> containing just the keys which you've specified in the claimNames var
   * args parameter.
   *
   * <p>If a given key name does not exist in the decoded JWT, then the value provided in the
   * returned map will be <code>null</code>
   *
   * @param request - HttpServletRequest with JWT Bearer token
   * @param claimNames - A variable number of claimNames to be included in the returned map
   * @throws SoffitAuthException - if verification fails at any point
   * @return Map<String, Claim> - a map of desired Claims with String keys
   */
  public Map<String, Claim> getClaimsFromJWT(HttpServletRequest request, String... claimNames)
      throws SoffitAuthException {
    String jwt = getBearerToken(request);
    DecodedJWT decoded = verifyToken(jwt);
    Map<String, Claim> allClaims = decoded.getClaims();

    Map<String, Claim> userMap = new HashMap<>();

    for (String claimName : claimNames) {
      userMap.put(claimName, allClaims.get(claimName));
    }

    return userMap;
  }
}
