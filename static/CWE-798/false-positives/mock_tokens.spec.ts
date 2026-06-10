// FALSE POSITIVE — not secrets.
// Resembles: bearer-token / JWT / api-key rules.
// Why benign: hand-written mock tokens for HTTP mocking in tests. They match the shape
// of real tokens but are nonsense bytes used only to assert request wiring.

import { describe, it, expect, vi } from "vitest";

const MOCK_BEARER = "Bearer mock.access.token.not.real.0000";
const MOCK_REFRESH = "rt_mock_0000000000000000000000000000";

describe("auth client", () => {
  it("attaches the bearer header", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    const client = makeClient({ token: MOCK_BEARER, fetch: fetchSpy });
    await client.getProfile();
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ headers: { Authorization: MOCK_BEARER } }),
    );
  });
});
