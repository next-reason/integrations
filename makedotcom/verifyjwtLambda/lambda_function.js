import { JwtVerifier } from "aws-jwt-verify";

const verifier = JwtVerifier.create({
  issuer: "https://id.eu.nextreason.com/", // set this to the expected "iss" claim on your JWTs
  audience: "https://webhook.site/workflows-enrich-test", // set this to the expected "aud" claim on your JWTs
  jwksUri: "https://id.eu.nextreason.com/.well-known/jwks.json", // set this to the JWKS uri from your OpenID configuration
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}