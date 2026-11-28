import {json} from './sessions.js';
import {importBrowserKeyring} from './browser-keyring.js';
import {cleanupIdentity} from './identity-cleanup.js';
import {runContextCleanup,contextCleanupStatus} from './context-config.js';

// Deployment bootstrap only. Authentication intentionally stays unavailable
// until the separately reviewed cross-origin/passkey protocol is integrated.
// No keys, identities, tokens or synthetic data are created by this handler.
export function createDeploymentWorker() {
  let keyCheck, keyConfiguration;
  return {
    async scheduled(event,env,ctx) {
      if(env?.DEPLOYMENT_STAGE!=='bootstrap'||!env?.DB?.prepare)return;
      // Housekeeping only, no auth routes are enabled. Fixed per-table cap.
      const work=Promise.all([cleanupIdentity({db:env.DB,limit:100}),runContextCleanup({db:env.DB,env})]);
      if(ctx?.waitUntil)ctx.waitUntil(work);else await work;
    },
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname === '/health' && ['GET', 'HEAD'].includes(request.method)) {
        return json({service: 'otpanda-api', status: 'setup-required', authentication: 'disabled'}, 200);
      }
      if (url.pathname === '/ready' && request.method === 'GET') {
        try {
          if (env?.DEPLOYMENT_STAGE !== 'bootstrap' || !env?.DB?.prepare) throw new Error();
          if(typeof env.ENCRYPTION_KEYRING!=='string'||typeof env.ACTIVE_KEY_ID!=='string')throw new Error();
          const current=[env.ENCRYPTION_KEYRING,env.ACTIVE_KEY_ID];
          if(keyConfiguration&&current.some((v,i)=>v!==keyConfiguration[i]))throw new Error();
          if(!keyCheck){keyConfiguration=current;keyCheck=importBrowserKeyring(env).then(()=>true,()=>false);}
          if(!await keyCheck)throw new Error();
          // A harmless read checks all required schema generations, not merely
          // the presence of a DB binding. Never return counts or private data.
          await env.DB.prepare('SELECT a.owner_id FROM accounts a LEFT JOIN identities i ON i.owner_id=a.owner_id LEFT JOIN sources s ON s.owner_id=a.owner_id LEFT JOIN entries e ON e.owner_id=a.owner_id LEFT JOIN entry_shares sh ON sh.entry_id=e.entry_id LEFT JOIN entry_tokens t ON t.entry_id=e.entry_id LEFT JOIN service_routes r ON r.entry_id=e.entry_id WHERE 0').all();
          return json({service: 'otpanda-api', database: 'available', keyring: 'valid-format', application: 'setup-required', context: await contextCleanupStatus({db: env.DB, env})}, 200);
        } catch {
          return json({error: 'unavailable'}, 503);
        }
      }
      if (url.pathname === '/v1' || url.pathname.startsWith('/v1/') || url.pathname === '/auth' || url.pathname.startsWith('/auth/')) {
        return json({error: 'setup_required'}, 503);
      }
      return json({error: 'not_found'}, 404);
    },
  };
}
export default createDeploymentWorker();
