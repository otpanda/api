import {createAppSignupHttp} from './app-signup-http.js';
// Unmounted composition. Runtime owner must supply trusted provider address and
// waitUntil. No request header is promoted to trusted metadata here.
import{SignupEmailService}from'./signup-email.js';import{PasskeySignupService}from'./passkey-signup.js';import{SignupHandoffService}from'./signup-handoff.js';import{WebLoginHandoffService}from'./web-login-handoff.js';import{DeviceSessionService}from'./device-sessions.js';import{BrowserExchangeService}from'./browser-exchanges.js';import{createSignupHttp}from'./signup-http.js';
export function createSignupPreparationRuntime({db,deliver,clock=Date.now,maxDeferred=4,signupAllowed}={}){
 if(!db||typeof deliver!=='function'||!Number.isSafeInteger(maxDeferred)||maxDeferred<1||maxDeferred>8)throw new TypeError('Bounded signup runtime required');
 let active=0;
 const signupEmail=new SignupEmailService(db,{deliver,clock,signupAllowed}),signup=new PasskeySignupService(db,{clock,signupAllowed}),sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:'https://otpanda.github.io/app/'}),login=new WebLoginHandoffService(db,{clock,sessions,exchanges,passkeys:{}}),handoff=new SignupHandoffService(db,{clock,signup,login});
 return{async fetch(request,{clientAddress,waitUntil}={}){
  if(typeof waitUntil!=='function')return new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});
  const defer=work=>{
   // Saturation is an account-independent visible busy response; no
   // in-memory queue and no unbounded background creation. Provider adapter
   // must impose its own actual request timeout. A deadline alone cannot stop
   // arbitrary injected work and is not claimed to do so.
   if(active>=maxDeferred){const error=new Error('Signup busy');error.code='signup_busy';throw error;}
   active++;const pending=Promise.resolve().then(work).catch(()=>{}).finally(()=>{active--;});
   try{waitUntil(pending);}catch{ /* Work already scheduled remains bounded. */ }
  };
  const factory=new URL(request.url).pathname==='/auth/signup/app'?createAppSignupHttp:createSignupHttp;return factory({db,signupEmail,handoff,clock,defer}).fetch(request,{clientAddress});
 }};
}
