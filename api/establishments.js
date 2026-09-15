import state, { json } from "./_state.js";

export default function handler(request, response) {
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method !== "GET") {
    return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const id = request.query.establishment_id || request.query.id;
  if (id) {
    const establishment = state.establishments.get(String(id));
    return json(response, establishment ? 200 : 404,
      establishment || { error: "ESTABLISHMENT_NOT_FOUND" });
  }
  return json(response, 200, {
    establishments: [...state.establishments.values()]
  });
}
