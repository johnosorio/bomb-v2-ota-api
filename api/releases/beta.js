import { makeReleaseHandler } from "./_release.js";

export default makeReleaseHandler(new URL("../../release-beta.json", import.meta.url));
