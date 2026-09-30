import { readFileSync } from "node:fs";

export function makeReleaseHandler(releaseUrl) {
  const release = JSON.parse(readFileSync(releaseUrl, "utf8"));
  return function handler(request, response) {
    const origin = `${request.headers["x-forwarded-proto"] || "https"}://${request.headers.host}`;
    const firmwareUrl = release.firmware_url.startsWith("http")
      ? release.firmware_url
      : `${origin}${release.firmware_url}`;
    response.status(200).json({ ...release, firmware_url: firmwareUrl });
  };
}
