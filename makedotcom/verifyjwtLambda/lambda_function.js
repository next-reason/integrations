import { JwtVerifier } from "aws-jwt-verify";

const verifier = JwtVerifier.create({
  issuer: "https://NEXT_IDENTITY_URL/", // set this to the expected "iss" claim on your JWTs
  audience: "AUD_CLAIM", // set this to the expected "aud" claim on your JWTs
  jwksUri: "https://NEXT_IDENTITY_URL/.well-known/jwks.json", // set this to the JWKS uri from your OpenID configuration
});

try {
  const payload = await verifier.verify("token");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}