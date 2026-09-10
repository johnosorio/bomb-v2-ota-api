export default function handler(request, response) {
  response.status(200).json({ service: "bomb-v2-ota-dummy", status: "ok" });
}
