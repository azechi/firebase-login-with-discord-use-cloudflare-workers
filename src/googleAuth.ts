import { base64UrlEncode } from './base64Url';

export { generateJwt, createCustomToken, importKey }

export interface KeyInfo {
  client_email: string;
  private_key: string;
  private_key_id: string;
}



async function createCustomToken(key: CryptoKey, client_email: string, localId: string){
  
  const iat = Math.floor(Date.now() /1000);
  const exp = iat + 3600;

  const payload = base64UrlEncode(
    new TextEncoder().encode(
    JSON.stringify({
      iss: client_email,
      sub: client_email,
      aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
      iat: iat,
      exp: exp,
      uid: localId,
    }))
  );

  const header = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        typ: "JWT",
        alg: "RS256",
      })
    )
  );
  

  const sign = base64UrlEncode(await crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    },
    key,
    new TextEncoder().encode(`${header}.${payload}`)
  ));

  return `${header}.${payload}.${sign}`


}


async function generateJwt(
  aud: string,
  {private_key, private_key_id, client_email}: KeyInfo
) {
 
  const iat = Math.floor(Date.now() /1000);
  const exp = iat + 3600;

  const payload = base64UrlEncode(
    new TextEncoder().encode(
    JSON.stringify({
      iss: client_email,
      sub: client_email,
      aud: aud,
      iat: iat,
      exp: exp,
    }))
  );

  const header = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        typ: "JWT",
        alg: "RS256",
        kid: private_key_id,
      })
    )
  );
  
  const key = await importKey(private_key);

  const sign = base64UrlEncode(await crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    },
    key,
    new TextEncoder().encode(`${header}.${payload}`)
  ));

  return `${header}.${payload}.${sign}`

}


function importKey(pem: string){
  const HEADER = "-----BEGIN PRIVATE KEY-----\n";
  const FOOTER = "-----END PRIVATE KEY-----\n";
  
  const contents = pem.substring(HEADER.length, pem.length - FOOTER.length);

  const der = new Uint8Array(
    (function* (s) {
      for (let i = 0, len = s.length; i < len; i++) {
        yield s.charCodeAt(i);
      }
    })(atob(contents))
  );

  return crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' },
    },
    true,
    ["sign"]
  );
}
