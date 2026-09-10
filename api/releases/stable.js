import release from "../../release.json";

export default function handler(request, response) {
  const origin = `${request.headers["x-forwarded-proto"] || "https"}://${request.headers.host}`;
  const firmwareUrl = release.firmware_url.startsWith("http")
    ? release.firmware_url
    : `${origin}${release.firmware_url}`;
  response.status(200).json({ ...release, firmware_url: firmwareUrl });
}
