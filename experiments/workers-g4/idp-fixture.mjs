// Controlled synthetic IdP for G4 qualification, never an external-login claim.
const enc=new TextEncoder();
const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const unb64=value=>Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
const hmac=secret=>crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
export async function fixture(request,env){
 const url=new URL(request.url);if(!url.pathname.startsWith('/fixture/'))return null;
 const jwk=JSON.parse(env.IDP_JWK),headers={'cache-control':'no-store'};
 if(url.pathname==='/fixture/jwks')return Response.json({keys:[{kty:'RSA',n:jwk.n,e:jwk.e,kid:'g4-fixture',alg:'RS256',use:'sig'}]},{headers});
 if(url.pathname==='/fixture/authorize'){
  if(request.headers.get('x-proof-key')!==env.PROOF_KEY)return new Response('Not found',{status:404});
  const q=url.searchParams;if(q.get('client_id')!=='g4-proof'||q.get('redirect_uri')!==url.origin+'/auth/oidc/callback'||q.get('code_challenge_method')!=='S256')return new Response('Invalid fixture request',{status:400});
  const payload=b64(enc.encode(JSON.stringify({nonce:q.get('nonce'),challenge:q.get('code_challenge'),exp:Date.now()+60000,redirect:q.get('redirect_uri')})));
  const code=payload+'.'+b64(await crypto.subtle.sign('HMAC',await hmac(env.OIDC_SECRET),enc.encode(payload)));
  const callback=new URL(q.get('redirect_uri'));callback.searchParams.set('state',q.get('state'));callback.searchParams.set('code',code);
  return new Response(null,{status:302,headers:{...headers,location:callback.href}});
 }
 if(url.pathname==='/fixture/token'&&request.method==='POST'){
  const q=new URLSearchParams(await request.text());if(q.get('client_secret')!==env.OIDC_SECRET||q.get('client_id')!=='g4-proof')return new Response('Invalid client',{status:401});
  try{
   const [payload,signature]=q.get('code').split('.');if(!await crypto.subtle.verify('HMAC',await hmac(env.OIDC_SECRET),unb64(signature),enc.encode(payload)))throw Error();
   const code=JSON.parse(new TextDecoder().decode(unb64(payload)));if(code.exp<Date.now()||code.redirect!==q.get('redirect_uri')||code.challenge!==b64(await crypto.subtle.digest('SHA-256',enc.encode(q.get('code_verifier')))))throw Error();
   const now=Math.floor(Date.now()/1000),head=b64(enc.encode(JSON.stringify({alg:'RS256',kid:'g4-fixture',typ:'JWT'}))),claims=b64(enc.encode(JSON.stringify({iss:url.origin,sub:'g4-controlled-subject',aud:'g4-proof',iat:now,exp:now+300,nonce:code.nonce})));
   const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);const sig=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,enc.encode(head+'.'+claims));
   return Response.json({id_token:head+'.'+claims+'.'+b64(sig),token_type:'Bearer',access_token:'synthetic-unused'},{headers});
  }catch{return Response.json({error:'invalid_grant'},{status:400,headers})}
 }
 return new Response('Not found',{status:404});
}
