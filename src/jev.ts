// The two judgments agent-scrub asks TypeSafe's Jev for. Neither request ever carries a
// credential: values are described in words and every context is built from a masked copy.

const ENDPOINT = "https://api.typesafe.ai/v1/systemone";
const BATCH = 20;

export type Ask = (state: unknown, questions: Record<string, { type: "noul"; instructions: string }>) => Promise<Record<string, number>>;

/** An `Ask` over Jev's HTTP API, or undefined without a key. */
export function jevClient(key: string | undefined, fetchImpl: typeof fetch = fetch): Ask | undefined {
  if (!key) return undefined;
  return async (state, questions) => {
    let lastError: unknown;
    for (const delay of [0, 2_000]) {
      if (delay) await new Promise((r) => setTimeout(r, delay));
      try {
        const response = await fetchImpl(ENDPOINT, {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          body: JSON.stringify({ model: "jev-latest", state, questions }),
          signal: AbortSignal.timeout(20_000),
        });
        const text = await response.text();
        if (!response.ok) throw new Error(`Jev HTTP ${response.status}: ${text.slice(0, 200)}`);
        const answers = (JSON.parse(text) as { answers: Record<string, { noul?: number }> }).answers;
        return Object.fromEntries(Object.entries(answers).map(([id, a]) => [id, a.noul ?? 0.5]));
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError;
  };
}

export interface Candidate {
  context: string;
  value: string;
}

/** P(credential) for each generic hit, from the text around it and a description of the value. */
export async function triage(ask: Ask, candidates: Candidate[]): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < candidates.length; i += BATCH) {
    const batch = candidates.slice(i, i + BATCH);
    const state = Object.fromEntries(batch.map((c, j) => [`c${j}`, c]));
    const questions = Object.fromEntries(
      batch.map((_, j) => [
        `c${j}`,
        {
          type: "noul" as const,
          instructions: `Does \`c${j}\` hold a secret credential (API key, token, password) as opposed to a name, identifier, hash or placeholder? \`context\` is the surrounding text with the value replaced by <VALUE>; \`value\` describes it.`,
        },
      ]),
    );
    const answers = await ask(state, questions);
    out.push(...batch.map((_, j) => answers[`c${j}`] ?? 0.5));
  }
  return out;
}

