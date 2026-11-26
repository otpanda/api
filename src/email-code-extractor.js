// Pure verification-code extraction from an already normalized email. It never
// fetches mail and never returns the message body.
const KEYWORD=/(verification|verify|security|one[- ]time|passcode|login|log[- ]in|sign[- ]in|confirmation|authentication|code|otp|pin)/i;
const DEFAULT_LIFETIME=10*60*1000, MAX_LIFETIME=24*60*60*1000;
export function extractEmailCode(text){
  if(typeof text!=='string'||!text||text.length>100000)return null;
  const re=/(?<![\w$%+.-])(\d{3}[ -]\d{3}|\d{4}[ -]\d{4}|\d{4,8})(?![\w%.]*\d)(?!\s?(?:minutes?|mins?|hours?|usd|eur|\$|%))/gi;
  let best=null;
  for(const m of text.matchAll(re)){
    const raw=m[1],digits=raw.replace(/[ -]/g,'');
    if(digits.length<4||digits.length>8)continue;
    const before=text.slice(Math.max(0,m.index-50),m.index),after=text.slice(m.index+raw.length,m.index+raw.length+30);
    let score=0;
    if(KEYWORD.test(before))score+=2;
    if(/^\s*(is|:)/i.test(after)||/(is|:)\s*$/i.test(before))score+=1;
    if(KEYWORD.test(after.slice(0,15)))score+=1;
    if(/^(19|20)\d\d$/.test(digits)&&score<3)continue;
    if(/^\d{1,2}[/.:]/.test(after)||/[/.:]\d{1,2}$/.test(before.slice(-3)))continue;
    if(score<2)continue;
    if(!best||score>best.score)best={score,code:digits};
  }
  return best?best.code:null;
}
export function extractExpiry(text,receivedAt){
  const m=typeof text==='string'?text.match(/(?:expires?|valid)\s+(?:in|for|within)\s+(\d{1,3})\s*(minutes?|mins?|hours?)/i):null;
  let ms=DEFAULT_LIFETIME;
  if(m){const n=Number(m[1])*(/^h/i.test(m[2])?3600000:60000);if(n>0)ms=Math.min(n,MAX_LIFETIME);}
  return receivedAt+ms;
}
