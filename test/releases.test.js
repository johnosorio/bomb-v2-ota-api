import test from "node:test";
import assert from "node:assert/strict";
import handler from "../api/releases/[channel].js";

function invoke(channel, headers = {}) {
  const result = { statusCode: 200, body: undefined };
  const response = {
    status(code) {
      result.statusCode = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    }
  };
  handler({
    query: { channel },
    headers: {
      host: "ota.example.test",
      "x-forwarded-proto": "https",
      ...headers
    }
  }, response);
  return result;
}

test("channel handler preserves stable beta and dev manifest responses", () => {
  const stable = invoke("stable");
  assert.equal(stable.statusCode, 200);
  assert.equal(stable.body.channel, "stable");
  assert.equal(stable.body.firmware_url, "https://ota.example.test/firmware/bomb-manager-0.2.13.bin");
  assert.equal(stable.body.sha256.length, 64);
  assert.equal(stable.body.size, 1518080);

  const beta = invoke("beta");
  assert.equal(beta.statusCode, 200);
  assert.equal(beta.body.channel, "beta");
  assert.equal(beta.body.firmware_url, "https://ota.example.test/firmware/bomb-manager-beta-placeholder.bin");

  const dev = invoke("dev");
  assert.equal(dev.statusCode, 200);
  assert.equal(dev.body.channel, "dev");
  assert.equal(dev.body.firmware_url, "https://ota.example.test/firmware/bomb-manager-dev-0.2.18-dev.bin");
});

test("channel handler rejects unknown, array and prototype-like channel values", () => {
  for (const channel of ["unknown", ["stable"], "__proto__", "constructor"]) {
    const result = invoke(channel);
    assert.equal(result.statusCode, 404);
    assert.deepEqual(result.body, { error: "NOT_FOUND" });
  }
});
