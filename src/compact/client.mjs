// Compact viewer entry for the portal: binds the client to this app's connect.json / manifest.json.
import connect from './connect.json';
import manifest from './manifest.json';
import { CompactClient } from './client-core.mjs';

export { CompactClient, CompactError } from './client-core.mjs';
export const compact = new CompactClient({ connect, manifest });
