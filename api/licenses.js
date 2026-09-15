import state, { json } from "./_state.js";

function isValid(license) {
  return license.status === "ACTIVE" &&
    new Date(license.expires_at).getTime() > Date.now();
}

export default function handler(request, response) {
  if (request.method !== "GET") {
    return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const id = request.query.establishment_id;
  const licenses = [...state.licenses.values()].filter((license) =>
    !id || license.establishment_id === String(id));
  return json(response, 200, {
    licenses: licenses.map((license) => ({
      ...license,
      valid_now: isValid(license)
    }))
  });
}
