import { makeReleaseHandler } from "../../lib/releases.js";

// Map avoids inherited-property lookups for attacker-controlled query values.
const handlers = new Map([
  ["stable", makeReleaseHandler(new URL("../../release.json", import.meta.url))],
  ["beta", makeReleaseHandler(new URL("../../release-beta.json", import.meta.url))],
  ["dev", makeReleaseHandler(new URL("../../release-dev.json", import.meta.url))]
]);

export default function handler(request, response) {
  const channel = request.query?.channel;
  const releaseHandler = handlers.get(channel);
  if (!releaseHandler) return response.status(404).json({ error: "NOT_FOUND" });
  return releaseHandler(request, response);
}
