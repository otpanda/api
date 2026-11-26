import {json} from './sessions.js';
// Cache only successful synchronous construction. Fetch failures retain the
// dispatcher's existing handling; a failed factory retries on its next route.
export function lazyHttp(factory){let value;return{fetch(...args){try{value??=factory();}catch{const cors=args[0]?.headers?.get('origin')==='https://otpanda.github.io'?{'Access-Control-Allow-Origin':'https://otpanda.github.io',Vary:'Origin'}:{};return json({error:'unavailable'},503,{'Cache-Control':'no-store',...cors});}return value.fetch(...args);}};}
