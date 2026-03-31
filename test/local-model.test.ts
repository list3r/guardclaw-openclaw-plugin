import { afterEach, describe, expect, it, vi } from "vitest";
import { desensitizeWithLocalModel, detectByLocalModel } from "../src/local-model.js";
import type { DetectionContext, PrivacyConfig } from "../src/types.js";

// Returns the first fetch call body whose JSON has a `messages` array
// (the LLM inference call, not an embedding call).
function findLlmCallBody(fetchSpy: ReturnType<typeof vi.spyOn>): Record<string, unknown> {
  for (const [, init] of fetchSpy.mock.calls) {
    try {
      const body = JSON.parse(init?.body as string) as Record<string, unknown>;
      if (Array.isArray(body.messages)) return body;
    } catch { /* skip */ }
  }
  throw new Error("No LLM call found in fetch spy calls");
}

describe("GuardClaw local-model request body", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("injects disable-thinking params for detection requests", async () => {
    // detectByLocalModel may call fetch twice: once for embedding (few-shot)
    // and once for the actual LLM inference. Mock both with a valid response.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          choices: [
            {
              message: {
                content: '{"level":"S1","reason":"safe","confidence":0.9}',
              },
            },
          ],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    const context: DetectionContext = {
      checkpoint: "onUserMessage",
      message: "hello world",
      sessionKey: "session-1",
    };
    const config: PrivacyConfig = {
      localModel: {
        enabled: true,
        type: "openai-compatible",
        endpoint: "http://localhost:11434",
        model: "Qwen/Qwen3.5-35B-A3B",
      },
    };

    const result = await detectByLocalModel(context, config);
    expect(result.level).toBe("S1");
    expect(fetchSpy).toHaveBeenCalled();

    const requestBody = findLlmCallBody(fetchSpy);
    expect(requestBody.chat_template_kwargs).toEqual({ enable_thinking: false });
  });

  it("injects disable-thinking params for PII extraction requests", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ choices: [{ message: { content: "[]" } }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const config: PrivacyConfig = {
      localModel: {
        enabled: true,
        type: "openai-compatible",
        endpoint: "http://localhost:11434",
        model: "Qwen/Qwen3.5-35B-A3B",
      },
    };

    const output = await desensitizeWithLocalModel("name: Alice, phone: 123", config);
    expect(output.wasModelUsed).toBe(true);
    expect(fetchSpy).toHaveBeenCalled();

    const requestBody = findLlmCallBody(fetchSpy);
    expect(requestBody.chat_template_kwargs).toEqual({ enable_thinking: false });
  });
});
