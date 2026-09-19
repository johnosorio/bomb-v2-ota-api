import { makeReleaseHandler } from "./_release.js";

export default makeReleaseHandler(new URL("../../release-dev.json", import.meta.url));
