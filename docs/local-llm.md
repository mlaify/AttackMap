# LLM passes on a local model

`--llm`, `--hunt`, `--triage` and `--remediate` can run on a model served on
your own machine or network, with no cloud round-trip:

```sh
ollama serve &                        # or llama-server, vLLM, LM Studio
ollama pull qwen2.5-coder:32b
attackmap analyze . --llm --llm-provider local --llm-model qwen2.5-coder:32b
```

- **Protocol**: OpenAI-compatible Chat Completions (`POST <base>/chat/completions`).
  Ollama, llama.cpp `llama-server`, vLLM and LM Studio all serve it. The call uses
  the Python standard library only.
- **Server**: `--llm-base-url` or `ATTACKMAP_LOCAL_LLM_URL` (default
  `http://127.0.0.1:11434/v1`, Ollama). **Model**: `--llm-model` or
  `ATTACKMAP_LOCAL_LLM_MODEL` (required).
- **Local-first**: the evidence pack is sent only to loopback, private
  (RFC 1918 / ULA) or link-local addresses and `localhost` names. Any other host
  is refused unless you set `ATTACKMAP_LOCAL_LLM_ALLOW_REMOTE=1`.
- **Context length**: evidence packs are large. Ollama's OpenAI endpoint uses the
  model's default context (often 2,048–4,096 tokens) and silently truncates
  the input. Raise it, for example with `OLLAMA_CONTEXT_LENGTH=32768 ollama serve`
  or `PARAMETER num_ctx 32768` in a Modelfile. Check `usage.input_tokens` in
  `defensive-review-llm.meta.json`: a round number such as 4096 means the input
  was cut.
- **Model choice**: grounding (citing `finding:N`, `chain:N`, … from the pack)
  needs a capable instruction-following model. A 30B-class coder model is a
  reasonable floor; small models run but produce ungrounded prose.

Verified against Ollama with `qwen2.5:0.5b` (wiring) on 2026-11-24.
