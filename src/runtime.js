import {CodeCipher} from './code-cipher.js';
import {SessionService} from './sessions.js';
import {SourceEntryStore} from './source-entries.js';
import {ServiceMetadata} from './service-metadata.js';
import {EntryAccess} from './entry-access.js';
import {EntryTokenStore} from './entry-tokens.js';
import {createEntryApplication} from './entry-application.js';

// Explicit deployment composition. No credentials, keys, sources or accounts
// are created here. The host owns platform metadata and approved provisioning.
export async function createRuntime({db,origin,keys,activeKeyId,trustedRequestKey,clock=Date.now}={}){
 if(!db||typeof db.prepare!=='function'||typeof db.batch!=='function'||typeof trustedRequestKey!=='function'||typeof clock!=='function')throw new TypeError('Complete runtime configuration required');
 const sessions=new SessionService(db,{origin,clock}),cipher=new CodeCipher({keys,activeKeyId});
 const metadata=new ServiceMetadata(db),sources=new SourceEntryStore(db,cipher,{matcher:metadata});
 const access=new EntryAccess(db,sources),tokens=new EntryTokenStore(db,access);
 return createEntryApplication({db,sessions,sources,metadata,access,tokens,trustedRequestKey,clock});
}
