import { json } from './sessions.js';
import { createSharingManageHttp } from './sharing-manage-http.js';
import { createMachineHandler } from './machine-access.js';

// Smallest composition candidate for the staged sharing and machine routes:
// one fetch entry that mounts the owner manage routes and the machine code
// read side by side. Deployment adapter mounts only under explicit default-off flag.
// No environment is provisioned here and no authorization decision is made
// in this module: every check stays inside the composed handlers.
export {sharingManagementPaths} from './sharing-manage-http.js';
export function createSharingRoutesHttp({ db, access, reader, sessions, clock = Date.now, native = false } = {}) {
  if (!db || !access || !reader || !sessions) throw new TypeError('Complete sharing route dependencies required');
  const manage = createSharingManageHttp({ db, access, sessions, clock, native });
  const machine = createMachineHandler({ access, reader, clock });
  return {
    async fetch(request, meta) {
      const { pathname } = new URL(request.url);
      if (pathname === '/v1/machine/code') return machine.fetch(request, meta);
      if (pathname.startsWith('/v1/manage/sharing/') || pathname.startsWith('/v1/manage/machine/')) return manage.fetch(request, meta);
      return json({ error: 'not_found' }, 404);
    },
  };
}
