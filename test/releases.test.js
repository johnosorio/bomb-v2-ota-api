import test from "node:test";
import assert from "node:assert/strict";
import stable from "../api/releases/stable.js";
import beta from "../api/releases/beta.js";
import dev from "../api/releases/dev.js";

function invoke(handler, headers = {}) {
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
    headers: {
      host: "ota.example.test",
      "x-forwarded-proto": "https",
      ...headers
    }
  }, response);
  return result;
}

test("stable release manifest resolves relative firmware URL", () => {
  const result = invoke(stable);
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.channel, "stable");
  assert.equal(result.body.firmware_url,
    "https://ota.example.test/firmware/bomb-manager-0.2.13.bin");
  assert.equal(result.body.sha256.length, 64);
  assert.equal(result.body.size, 1518080);
});

test("beta and dev release handlers load their JSON fixtures", () => {
  const betaResult = invoke(beta);
  assert.equal(betaResult.statusCode, 200);
  assert.equal(betaResult.body.channel, "beta");
  assert.equal(betaResult.body.firmware_url,
    "https://ota.example.test/firmware/bomb-manager-beta-placeholder.bin");

  const devResult = invoke(dev);
  assert.equal(devResult.statusCode, 200);
  assert.equal(devResult.body.channel, "dev");
  assert.equal(devResult.body.firmware_url,
    "https://ota.example.test/firmware/bomb-manager-dev-0.2.18-dev.bin");
});
