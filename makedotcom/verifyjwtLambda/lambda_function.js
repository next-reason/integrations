export const handler = async (event, context) => {
  const jwt = event['token'];

  const isValid = verifyJwtSignature(jwt);
  console.log('JWT signature is valid:', isValid);
  const decodedPayload = JSON.parse(atob(jwt.split('.')[1]));
  
  
  async function verifyJwtSignature(jwt) {
      try {
          const [headerEncoded, payloadEncoded, signatureEncoded] = jwt.split('.');
          if (!headerEncoded || !payloadEncoded || !signatureEncoded) {
              throw new Error('Invalid JWT format');
          }
      
          const header = JSON.parse(atob(headerEncoded));
          const { kid, alg, jku } = header;
      
          if (!kid || !alg || !jku) {
              throw new Error('Missing kid, jku or alg in JWT header');
          }
      
          if (alg !== 'RS256') { // Enforce RS256
              throw new Error('Unsupported algorithm: ' + alg + '. Only RS256 is supported.');
          }
      
          const response = await fetch(header.jku);
          if (!response.ok) {
              throw new Error(`Failed to fetch JWKS: ${response.status}`);
          }
          const jwks = await response.json();
      
          const key = jwks.keys.find((k) => k.kid === kid);
          if (!key) {
              throw new Error('Key not found in JWKS');
          }
      
          if (key.kty !== 'RSA') {
              throw new Error('Unsupported key type. Only RSA keys are supported.');
          }
      
          const cryptoKey = await crypto.subtle.importKey(
              'jwk',
              key,
              { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
              false,
              ['verify']
          );
      
          const signature = base64UrlDecode(signatureEncoded);
          const data = new TextEncoder().encode(`${headerEncoded}.${payloadEncoded}`);
      
          const isValid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
          return isValid;
      
      } catch (error) {
          console.error('JWT verification failed:', error);
          return false;
      }
  }
      
  function base64UrlDecode(base64Url) {
      let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) {
          base64 += '=';
      }
      return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }
  
  //console.log(decodedPayload.events);
  
  
  return decodedPayload.events;
};