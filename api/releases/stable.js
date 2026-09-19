import { makeReleaseHandler } from "./_release.js";

export default makeReleaseHandler(new URL("../../release.json", import.meta.url));
