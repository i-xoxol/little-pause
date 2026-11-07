// Web Crypto only. Passwords, recovery secrets and plaintext never leave this module's caller.
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', {fatal: true});
export const ITERATIONS = 600000;
export const random = n => crypto.getRandomValues(new Uint8Array(n));
export const b64 = bytes => {let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(binary).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');};
export function unb64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid encrypted data');
  return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4)), c=>c.charCodeAt(0));
}
async function hkdf(raw, salt, info, aes=false) {
  const material=await crypto.subtle.importKey('raw',raw,'HKDF',false,['deriveBits','deriveKey']);
  const params={name:'HKDF',hash:'SHA-256',salt:enc.encode(salt),info:enc.encode('little-pause:v1:'+info)};
  return aes ? crypto.subtle.deriveKey(params,material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']) : new Uint8Array(await crypto.subtle.deriveBits(params,material,256));
}
export async function passwordKeys(password,salt) {
  if (typeof password!=='string' || password.length>1024) throw Error('Invalid password');
  const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  const master=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:unb64(salt),iterations:ITERATIONS},material,256));
  try {return {wrap:await hkdf(master,'','password-wrap',true),auth:b64(await hkdf(master,'','authentication'))};}
  finally {master.fill(0);}
}
export async function seal(key,raw,aad) {
  const iv=random(12);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(aad),tagLength:128},key,raw);
  return {v:1,iv:b64(iv),ct:b64(new Uint8Array(ciphertext))};
}
export async function open(key,envelope,aad) {
  if(envelope.v!==1||unb64(envelope.iv).length!==12)throw Error('Unsupported encrypted data');
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(envelope.iv),additionalData:enc.encode(aad),tagLength:128},key,unb64(envelope.ct)));
}
const wrapAAD=(id,kind)=>`lp:v1:vault:${id}:${kind}`;
export const importVault=raw=>crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
export const wrapVault=(raw,key,id,kind='password')=>seal(key,raw,wrapAAD(id,kind));
export const unwrapVault=(envelope,key,id,kind='password')=>open(key,envelope,wrapAAD(id,kind));
export function makeRecoveryKey() {
  const hex=[...random(32)].map(x=>x.toString(16).padStart(2,'0')).join('');
  return 'LP1-'+hex.match(/.{8}/g).join('-');
}
export async function recoveryKeys(text,id) {
  const hex=text.trim().replace(/^LP1-/i,'').replaceAll('-','').replaceAll(' ','');
  if(!/^[a-fA-F0-9]{64}$/.test(hex))throw Error('Enter the complete recovery key from your recovery kit.');
  const secret=Uint8Array.from(hex.match(/../g),x=>parseInt(x,16));
  try {return {wrap:await hkdf(secret,id,'recovery-wrap',true),auth:b64(await hkdf(secret,id,'recovery-proof'))};}
  finally {secret.fill(0);}
}
export async function createVault(password) {
  const id=crypto.randomUUID(),salt=b64(random(32)),raw=random(32),recoveryKey=makeRecoveryKey();
  try {
    const p=await passwordKeys(password,salt),r=await recoveryKeys(recoveryKey,id);
    return {id,salt,auth:p.auth,recoveryAuth:r.auth,passwordWrap:await wrapVault(raw,p.wrap,id),recoveryWrap:await wrapVault(raw,r.wrap,id,'recovery'),key:await importVault(raw),recoveryKey};
  } finally {raw.fill(0);}
}
export const encryptEntry=(key,vaultId,id,version,value)=>seal(key,enc.encode(JSON.stringify(value)),`lp:v1:entry:${vaultId}:${id}:${version}`);
export async function decryptEntry(key,vaultId,row) {
  const raw=await open(key,row.envelope,`lp:v1:entry:${vaultId}:${row.id}:${row.version}`);
  try {const value=JSON.parse(dec.decode(raw));if(typeof value.title!=='string'||typeof value.body!=='string')throw Error('Invalid entry');return value;}
  finally {raw.fill(0);}
}
