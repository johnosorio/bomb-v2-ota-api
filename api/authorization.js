import state, { json } from "./_state.js";

function isValid(license) {
  return license.status === "ACTIVE" &&
    new Date(license.expires_at).getTime() > Date.now();
}

export default function handler(request, response) {
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method !== "GET") {
    return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const establishmentId = String(request.query.establishment_id || "");
  if (!establishmentId) {
    return json(response, 400, { error: "establishment_id es obligatorio" });
  }
  const establishment = state.establishments.get(establishmentId);
  if (!establishment) {
    return json(response, 404, { error: "ESTABLISHMENT_NOT_FOUND" });
  }
  const license = [...state.licenses.values()]
    .filter((item) => item.establishment_id === establishmentId &&
      item.status === "ACTIVE")
    .sort((left, right) =>
      new Date(right.updated_at) - new Date(left.updated_at))[0];
  if (!license) return json(response, 404, { error: "LICENSE_NOT_FOUND" });

  return json(response, 200, {
    schema_version: 1,
    establishment_id: establishmentId,
    establishment_name: establishment.name,
    valid_now: isValid(license),
    license_id: license.license_id,
    expires_at: license.expires_at,
    contracted_capacity: license.contracted_capacity,
    authorized_bombs: license.authorized_bombs,
    allowed_games: license.allowed_games,
    origin: "DEMO",
    signature: license.signature
  });
}
