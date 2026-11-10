import jwt from 'jsonwebtoken';
import { z } from 'zod';
export const credentials=z.object({email:z.string().email().max(200),password:z.string().min(8).max(128)});
export function issueToken(user) {return jwt.sign({sub:String(user._id),role:user.role},process.env.JWT_SECRET,{expiresIn:'2h',issuer:'webshield'});}
export function setAuthCookie(res,token) {res.cookie('ws_token',token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:7200000,path:'/'});}
export function auth(req,res,next) {
 try {const token=req.cookies.ws_token;const claims=jwt.verify(token,process.env.JWT_SECRET,{issuer:'webshield'});req.user=claims.sub;next();}
 catch {res.status(401).json({error:'Authentication required'});}
}
export function validateLabUrl(raw) {
 const u=new URL(raw);
 const allowed=(process.env.SCAN_ALLOWED_HOSTS||'lab').split(',').map(s=>s.trim()).filter(Boolean);
 if (!['http:','https:'].includes(u.protocol)||u.username||u.password||u.port && !['4000','80','443'].includes(u.port)||!allowed.includes(u.hostname))
  throw Error('Only explicitly allowlisted lab targets are supported');
 u.hash='';return u.toString();
}
