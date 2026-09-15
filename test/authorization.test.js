import test from "node:test";
import assert from "node:assert/strict";
import authorization from "../api/authorization.js";
import establishments from "../api/establishments.js";
import licenses from "../api/licenses.js";
import state from "../api/_state.js";

function invoke(handler, method, query = {}) {
  const result = { headers: {}, statusCode: 200, body: undefined };
  const response = {
    status(code) {
      result.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      result.headers[name] = value;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
    end() {
      result.ended = true;
      return this;
    }
  };
  handler({ method, query }, response);
  return result;
}

test("demo establishment 01 has an active least-privilege license", () => {
  const result = invoke(authorization, "GET", { establishment_id: "01" });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.schema_version, 1);
  assert.equal(result.body.establishment_id, "01");
  assert.equal(result.body.valid_now, true);
  assert.equal(result.body.authorized_bombs, 1);
  assert.deepEqual(result.body.allowed_games, ["standalone-demo"]);
  assert.equal(result.body.origin, "DEMO");
});

test("active but expired license is reported as not valid", () => {
  const license = state.licenses.get("demo-license-01");
  const expiresAt = license.expires_at;
  license.expires_at = "2000-01-01T00:00:00.000Z";
  const result = invoke(authorization, "GET", { establishment_id: "01" });
  license.expires_at = expiresAt;
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.valid_now, false);
});

test("establishment without an active license is rejected", () => {
  const license = state.licenses.get("demo-license-01");
  state.licenses.delete("demo-license-01");
  const result = invoke(authorization, "GET", { establishment_id: "01" });
  state.licenses.set("demo-license-01", license);
  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, "LICENSE_NOT_FOUND");
});

test("authorization rejects unknown establishments and missing IDs", () => {
  assert.equal(invoke(authorization, "GET").statusCode, 400);
  const missing = invoke(authorization, "GET", { establishment_id: "02" });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.body.error, "ESTABLISHMENT_NOT_FOUND");
});

test("establishment and license read endpoints expose the seeded demo record", () => {
  assert.equal(invoke(establishments, "GET", { id: "01" }).body.name,
    "Instalacion de prueba");
  const listed = invoke(licenses, "GET", { establishment_id: "01" });
  assert.equal(listed.body.licenses.length, 1);
  assert.equal(listed.body.licenses[0].valid_now, true);
});

test("commercial demo endpoints do not expose unauthenticated writes", () => {
  assert.equal(invoke(authorization, "POST").statusCode, 405);
  assert.equal(invoke(establishments, "POST").statusCode, 405);
  assert.equal(invoke(licenses, "POST").statusCode, 405);
});
