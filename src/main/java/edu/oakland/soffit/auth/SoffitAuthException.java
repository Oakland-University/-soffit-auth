package edu.oakland.soffit.auth;

/**
 * This class is the catch-all exception thrown by the soffit-auth library. It mainly wraps several
 * different exceptions thrown by auth0's JWT library, while providing more helpful error messages.
 *
 * <p>The following auth0 excpetions are wrapped:
 *
 * <ul>
 *   <li><code>InvalidClaimException</code> This exception, caught in the verifyToken method {@link
 *       AuthService#verifyToken}, is thrown when the JWT being verified doesn't have the claims
 *       that the verifier expects. For our use case, this tends to be an incorrect issuer claim. To
 *       help diagnose the problem, the AuthService will mention the likelihood of the issuer being
 *       incorrect, and it will log out the JWT in question.
 *   <li><code>JWTDecodeException</code> This exception, caught in the determineAlgorithm method
 *       {@link AuthService#determineAlgorithm}, is thrown when the token a user passed is not a
 *       valid JWT.
 *   <li><code>SignatureVerificationException</code> This exception, caught in the verifyToken
 *       method {@link AuthService#verifyToken}, is thrown when when the auth library's verifier
 *       can't verify a token for some reason. This is most often a result of an incorrect token.
 *   <li><code>TokenExpiredException</code> This exception, caught in the verifyToken method {@link
 *       AuthService#verifyToken}, is thrown when a JWT is passed whose expiration (exp) claim is
 *       before the current date/time. This exception is expected to be thrown often, and is not
 *       necessarily a sign of a serious problem. Verification of the JWT will fail due to an
 *       expired token, but it is inevitable that a backend will get them from time to time. To turn
 *       off this particular check (for development work), set the <code>
 *       org.apereo.portal.soffit.jwt.issuer</code> parameter to false in your project's
 *       application.properties
 * </ul>
 */
public class SoffitAuthException extends Exception {
  public SoffitAuthException(String message, Throwable cause) {
    super(message, cause);
  }
}
