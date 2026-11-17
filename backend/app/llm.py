"""LLM providers behind one small interface, so the AI features do not depend on a single vendor.

Two kinds of backends:
  * "anthropic"  - the Anthropic SDK (structured outputs, tool runner, server-side refusal fallbacks).
  * "openai"     - any OpenAI-compatible Chat Completions API over plain HTTP (no SDK): OpenAI, Google Gemini, Groq,
                   OpenRouter, Mistral, DeepSeek, a local Ollama, any custom endpoint, and the keyless free tier of Pollinations.

Every provider offers the same three calls:
  structured(system, content, schema)  -> (parsed pydantic object, model, usage)
  chat(system, messages, tools)        -> Reply   (tools: plain Python callables with type hints and an "Args:" docstring)
  complete(prompt)                     -> Reply
Every failure is raised as AiError with a message an operator can act on.
"""
from __future__ import annotations

import inspect
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from pydantic import BaseModel, ValidationError


class AiError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ catalog
@dataclass(frozen=True)
class Spec:
    id: str
    label: str
    kind: str                       # "anthropic" | "openai"
    default_model: str
    url: str = ""                   # Chat Completions URL (kind "openai"); editable when base_url_editable
    key_env: str | None = None      # environment variable that holds the key (takes precedence over the dashboard)
    needs_key: bool = True
    accepts_key: bool = True
    key_prefix: str | None = None   # a sanity check on keys typed into the dashboard
    key_url: str | None = None      # where to get a key
    base_url_editable: bool = False
    tools: bool = True              # multi-step tool use; False = the assistant gets one data snapshot in a single request
    free: str = ""                  # short note shown in the UI about cost
    destination: str = ""           # who receives the data (shown in the UI)
    retry_wait_max: int = 10        # wait at most this many seconds for a rate limit to clear before giving up


PROVIDERS: dict[str, Spec] = {s.id: s for s in (
    Spec("free", "Free AI (Pollinations, no key)", "openai", "openai", url="https://text.pollinations.ai/openai", needs_key=False, accepts_key=False,
         tools=False, retry_wait_max=60, free="Free, no key or sign-up. Limited to about one reply every 45 seconds per server; fine for simple work.",
         destination="Pollinations.ai, a public free service (do not use it for infrastructure you must keep confidential)"),
    Spec("anthropic", "Anthropic (Claude)", "anthropic", "claude-opus-5-5", key_env="ANTHROPIC_API_KEY", key_prefix="sk-ant-",
         key_url="https://console.anthropic.com/settings/keys", destination="Anthropic"),
    Spec("openai", "OpenAI", "openai", "gpt-5-mini", url="https://api.openai.com/v1/chat/completions", key_env="OPENAI_API_KEY", key_prefix="sk-",
         key_url="https://platform.openai.com/api-keys", destination="OpenAI"),
    Spec("gemini", "Google Gemini", "openai", "gemini-2.5-flash", url="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
         key_env="GEMINI_API_KEY", key_url="https://aistudio.google.com/apikey", free="Has a free tier (a Google account and key are needed).",
         destination="Google"),
    Spec("groq", "Groq", "openai", "llama-3.3-70b-versatile", url="https://api.groq.com/openai/v1/chat/completions", key_env="GROQ_API_KEY", key_prefix="gsk_",
         key_url="https://console.groq.com/keys", free="Has a free tier (sign-up and key needed).", destination="Groq"),
    Spec("openrouter", "OpenRouter", "openai", "meta-llama/llama-3.3-70b-instruct:free", url="https://openrouter.ai/api/v1/chat/completions",
         key_env="OPENROUTER_API_KEY", key_prefix="sk-or-", key_url="https://openrouter.ai/keys", free="Models ending in :free cost nothing (key needed).",
         destination="OpenRouter and the model's host"),
    Spec("mistral", "Mistral", "openai", "mistral-small-latest", url="https://api.mistral.ai/v1/chat/completions", key_env="MISTRAL_API_KEY",
         key_url="https://console.mistral.ai/api-keys", free="Has a free experiment tier (key needed).", destination="Mistral AI"),
    Spec("deepseek", "DeepSeek", "openai", "deepseek-chat", url="https://api.deepseek.com/v1/chat/completions", key_env="DEEPSEEK_API_KEY", key_prefix="sk-",
         key_url="https://platform.deepseek.com/api_keys", destination="DeepSeek"),
    Spec("ollama", "Ollama (local, private)", "openai", "llama3.2", url=os.getenv("OLLAMA_BASE_URL", "http://ollama:11434/v1").rstrip("/") + "/chat/completions",
         needs_key=False, base_url_editable=True, retry_wait_max=0, free="Free and private: runs on your own machine, nothing leaves your network.",
         destination="your own Ollama server (nothing leaves your network)"),
    Spec("custom", "Other OpenAI-compatible API", "openai", "", key_env="AI_API_KEY", needs_key=False, base_url_editable=True,
         destination="the endpoint you configure"),
)}
DEFAULT_PROVIDER = "free"


def catalog() -> list[dict]:
    """What the settings page needs to know about each provider (never any key)."""
    return [{"id": s.id, "label": s.label, "default_model": s.default_model, "needs_key": s.needs_key, "accepts_key": s.accepts_key, "key_env": s.key_env,
             "key_prefix": s.key_prefix, "key_url": s.key_url, "base_url_editable": s.base_url_editable, "default_base_url": _base_of(s.url),
             "tools": s.tools, "free": s.free, "destination": s.destination} for s in PROVIDERS.values()]


def _base_of(url: str) -> str:
    return url[: -len("/chat/completions")] if url.endswith("/chat/completions") else url


def spec(provider: str) -> Spec:
    if provider not in PROVIDERS:
        raise AiError(f"Unknown AI provider '{provider}'. Choose one under AI → Settings.")
    return PROVIDERS[provider]


# Prefixes that identify a provider's keys unambiguously. Used only to catch a key pasted under the wrong provider: key formats change
# (Google AI Studio issues both "AIza…" and "AQ.…" keys), so an unfamiliar shape is never rejected; Test connection is the real check.
DISTINCT_PREFIXES = {"anthropic": "sk-ant-", "openrouter": "sk-or-", "groq": "gsk_"}


def check_key_shape(provider: str, key: str) -> str | None:
    """A helpful message when a typed key cannot be right for this provider, else None."""
    s = spec(provider)
    if not s.accepts_key:
        return f"{s.label} does not use an API key. Leave the key empty."
    if any(c.isspace() for c in key):
        return "The API key contains spaces or line breaks. Paste it again as a single line."
    own = DISTINCT_PREFIXES.get(s.id)
    for other_id, prefix in DISTINCT_PREFIXES.items():
        if other_id != s.id and key.startswith(prefix) and not (own and key.startswith(own)):
            other = PROVIDERS[other_id]
            return f"That looks like a {other.label} key, but the provider is {s.label}. Pick {other.label}, or enter a {s.label} key."
    return None


# ------------------------------------------------------------------------------------------------ common types
@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens


@dataclass
class Reply:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    refused: bool = False


def _missing_key(s: Spec) -> AiError:
    where = f"Add {s.key_env} to .env, or enter a key under AI → Settings" if s.key_env else "Enter a key under AI → Settings"
    get = f" (get one at {s.key_url})" if s.key_url else ""
    return AiError(f"No API key is set for {s.label}. {where}{get}. Or switch to the free provider, which needs no key.")


def build(cfg: dict, decrypt: Callable[[str], str]) -> "Provider":
    """The provider chosen in the AI settings, with its key (environment first, then the dashboard) and model."""
    s = spec(cfg.get("provider") or DEFAULT_PROVIDER)
    key = resolve_key(s, cfg, decrypt)
    if s.needs_key and not key:
        raise _missing_key(s)
    model = (cfg.get("model") or "").strip() or s.default_model
    if not model:
        raise AiError(f"No model is set for {s.label}. Enter the model name under AI → Settings.")
    if s.kind == "anthropic":
        return AnthropicProvider(s, model, key)
    url = s.url
    if s.base_url_editable and (cfg.get("base_url") or "").strip():
        base = cfg["base_url"].strip().rstrip("/")
        url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    if not url:
        raise AiError(f"No API address is set for {s.label}. Enter its base URL (for example https://host/v1) under AI → Settings.")
    return OpenAICompatProvider(s, model, key, url)


def resolve_key(s: Spec, cfg: dict, decrypt: Callable[[str], str]) -> str:
    if s.key_env and os.getenv(s.key_env):
        return os.environ[s.key_env].strip()
    stored = (cfg.get("api_keys") or {}).get(s.id)
    if not stored:
        return ""
    try:
        return decrypt(stored)
    except Exception as error:  # noqa: BLE001
        raise AiError(f"The saved {s.label} key cannot be decrypted (was ENCRYPTION_KEY or JWT_SECRET changed?). Enter the key again under AI → Settings.") from error


def key_source(s: Spec, cfg: dict) -> str | None:
    if s.key_env and os.getenv(s.key_env):
        return "env"
    return "dashboard" if (cfg.get("api_keys") or {}).get(s.id) else None


class Provider:
    spec: Spec
    model: str

    def structured(self, system: str, content: str, schema: type[BaseModel], effort: str = "medium") -> tuple[BaseModel, str, Usage]:
        raise NotImplementedError

    def chat(self, system: str, messages: list[dict], tools: list[Callable], max_iterations: int = 10) -> Reply:
        raise NotImplementedError

    def complete(self, prompt: str) -> Reply:
        raise NotImplementedError


# ------------------------------------------------------------------------------------------------ Anthropic
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


def anthropic_client(key: str):
    try:
        import anthropic
    except ImportError as error:
        raise AiError("The anthropic Python package is not installed on this server (pip install anthropic), or choose another provider.") from error
    return anthropic.Anthropic(api_key=key, timeout=180.0, max_retries=2)


class AnthropicProvider(Provider):
    def __init__(self, s: Spec, model: str, key: str):
        self.spec, self.model, self.client = s, model, anthropic_client(key)

    def _extra(self) -> dict:
        """Server-side refusal fallbacks on the models that support them (a declined request is retried on a suitable model)."""
        return {"betas": [FALLBACK_BETA], "fallbacks": "default"} if self.model in FALLBACK_MODELS else {}

    @staticmethod
    def _usage(u) -> Usage:
        return Usage(int(getattr(u, "input_tokens", 0) or 0) + int(getattr(u, "cache_read_input_tokens", 0) or 0) + int(getattr(u, "cache_creation_input_tokens", 0) or 0),
                     int(getattr(u, "output_tokens", 0) or 0))

    def _error(self, error: Exception) -> AiError:
        import anthropic
        name = self.spec.label
        if isinstance(error, anthropic.AuthenticationError):
            return AiError(f"The {name} API key was rejected (invalid or revoked). Check it under AI → Settings" + (f" or in {self.spec.key_env}." if self.spec.key_env else "."))
        if isinstance(error, anthropic.PermissionDeniedError):
            return AiError(f"The {name} API key may not use the model '{self.model}'.")
        if isinstance(error, anthropic.NotFoundError):
            return AiError(f"The model '{self.model}' does not exist at {name}. Check the model name under AI → Settings.")
        if isinstance(error, anthropic.RateLimitError):
            return AiError(f"The {name} rate limit was reached. Try again in a minute.")
        if isinstance(error, anthropic.APIStatusError):
            return AiError(f"The {name} API returned an error ({error.status_code}).")
        if isinstance(error, anthropic.APIConnectionError):
            return AiError(f"Could not reach the {name} API from this server.")
        return AiError(str(error)[:200])

    def structured(self, system, content, schema, effort="medium"):
        import anthropic
        try:
            response = self.client.beta.messages.parse(model=self.model, max_tokens=16000, system=system, messages=[{"role": "user", "content": content}],
                                                       output_format=schema, output_config={"effort": effort}, **self._extra())
        except anthropic.APIError as error:
            raise self._error(error) from error
        usage = self._usage(response.usage)
        if response.stop_reason == "refusal":
            raise RefusedError("The model declined to answer this request.", usage)
        if response.stop_reason == "max_tokens" or response.parsed_output is None:
            raise AiError("The answer was cut off. Try again with less input.")
        return response.parsed_output, response.model, usage

    def chat(self, system, messages, tools, max_iterations=10):
        import anthropic
        from anthropic import beta_tool
        try:
            if tools:
                runner = self.client.beta.messages.tool_runner(model=self.model, max_tokens=16000, system=system, tools=[beta_tool(t) for t in tools],
                                                               messages=messages, max_iterations=max_iterations, **self._extra())
                final = runner.until_done()
            else:
                final = self.client.beta.messages.create(model=self.model, max_tokens=16000, system=system, messages=messages, **self._extra())
        except anthropic.APIError as error:
            raise self._error(error) from error
        text = "\n\n".join(b.text for b in final.content if b.type == "text").strip()
        return Reply(text, final.model, self._usage(final.usage), refused=final.stop_reason == "refusal")

    def complete(self, prompt):
        import anthropic
        try:
            r = self.client.messages.create(model=self.model, max_tokens=200, messages=[{"role": "user", "content": prompt}])
        except anthropic.APIError as error:
            raise self._error(error) from error
        return Reply("".join(b.text for b in r.content if b.type == "text"), r.model, self._usage(r.usage))


class RefusedError(AiError):
    def __init__(self, message: str, usage: Usage | None = None):
        super().__init__(message)
        self.usage = usage or Usage()


# ------------------------------------------------------------------------------------------------ OpenAI-compatible
_PY_TO_JSON = {str: "string", int: "integer", float: "number", bool: "boolean", "str": "string", "int": "integer", "float": "number", "bool": "boolean"}


def tool_schema(fn: Callable) -> dict:
    """An OpenAI function definition from a Python function's signature and Google-style docstring."""
    doc = inspect.getdoc(fn) or ""
    summary, _, args_part = doc.partition("\nArgs:")
    arg_docs = {m.group(1): m.group(2).strip() for m in re.finditer(r"^\s*(\w+):\s*(.+)$", args_part, re.M)}
    props, required = {}, []
    for name, p in inspect.signature(fn).parameters.items():
        if name == "self":
            continue
        prop: dict[str, Any] = {"type": _PY_TO_JSON.get(p.annotation, "string")}
        if name in arg_docs:
            prop["description"] = arg_docs[name]
        props[name] = prop
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return {"type": "function", "function": {"name": fn.__name__, "description": summary.strip()[:1000],
                                             "parameters": {"type": "object", "properties": props, "required": required}}}


def call_tool(fn: Callable, raw_args: str | dict | None) -> str:
    """Run one tool call from the model: tolerate bad JSON, unknown arguments and loosely typed values."""
    try:
        args = raw_args if isinstance(raw_args, dict) else json.loads(raw_args or "{}")
    except ValueError:
        return json.dumps({"error": "The tool arguments were not valid JSON."})
    if not isinstance(args, dict):
        args = {}
    params = inspect.signature(fn).parameters
    clean = {}
    for name, value in args.items():
        if name not in params:
            continue
        kind = _PY_TO_JSON.get(params[name].annotation)
        try:
            if kind == "boolean" and isinstance(value, str):
                value = value.strip().lower() in ("true", "1", "yes")
            elif kind == "integer" and not isinstance(value, bool):
                value = int(float(value))
            elif kind == "string" and value is not None and not isinstance(value, str):
                value = str(value)
        except (TypeError, ValueError):
            continue
        clean[name] = value
    try:
        return str(fn(**clean))
    except Exception as error:  # noqa: BLE001  (a tool failure is reported to the model, not raised)
        return json.dumps({"error": str(error)[:200]})


def _strip_reasoning(text: str) -> str:
    return re.sub(r"<think>[\s\S]*?</think>", "", text or "").strip()


def extract_json(text: str) -> Any:
    """The JSON object in a model's answer, also when wrapped in a ``` fence or surrounded by prose."""
    text = _strip_reasoning(text)
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                pass
    raise AiError("The model did not answer in the expected format. Try again, or choose a stronger model under AI → Settings.")


class OpenAICompatProvider(Provider):
    TIMEOUT = httpx.Timeout(180.0, connect=10.0)
    transport: httpx.BaseTransport | None = None      # tests replace this with an httpx.MockTransport

    def __init__(self, s: Spec, model: str, key: str, url: str):
        self.spec, self.model, self.key, self.url = s, model, key, url

    # --------------------------------------------------------------------- HTTP
    def _post(self, body: dict) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        if self.spec.id == "openrouter":
            headers["X-Title"] = "SM-Watch"
        body = {"model": self.model, **body}
        waited = 0.0
        for attempt in range(3):
            try:
                with httpx.Client(timeout=self.TIMEOUT, transport=self.transport) as client:
                    r = client.post(self.url, json=body, headers=headers)
            except httpx.TimeoutException as error:
                raise AiError(f"{self.spec.label} did not answer within {int(self.TIMEOUT.read or 0)} seconds. Try again, or with less input.") from error
            except httpx.HTTPError as error:
                hint = " Is Ollama running and reachable from the SM-Watch containers?" if self.spec.id == "ollama" else ""
                raise AiError(f"Could not reach {self.spec.label} at {_base_of(self.url)}: {type(error).__name__}.{hint}") from error
            if r.status_code in (429, 402, 503) and attempt < 2:
                wait = self._retry_after(r)
                if wait is not None and waited + wait <= self.spec.retry_wait_max:
                    time.sleep(wait)
                    waited += wait
                    continue
            if r.status_code >= 400:
                raise self._error(r)
            try:
                return r.json()
            except ValueError as error:
                raise AiError(f"{self.spec.label} returned something that is not JSON (is the base URL right? It usually ends in /v1).") from error
        raise AiError(f"{self.spec.label} is busy. Try again shortly.")

    @staticmethod
    def _retry_after(r: httpx.Response) -> float | None:
        value = r.headers.get("retry-after")
        if value is None:
            m = re.search(r"[Rr]etry after (\d+)\s*s", r.text)
            value = m.group(1) if m else None
        try:
            return max(0.5, float(value)) if value is not None else None
        except ValueError:
            return None

    def _error(self, r: httpx.Response) -> AiError:
        name, code = self.spec.label, r.status_code
        try:
            body = r.json()
            err = body.get("error") if isinstance(body, dict) else None
            detail = (err.get("message") if isinstance(err, dict) else err) or (body.get("message") if isinstance(body, dict) else None) or ""
        except ValueError:
            detail = r.text
        detail = re.sub(r"\s+", " ", str(detail)).strip()[:240]
        where = f" (or {self.spec.key_env} in .env)" if self.spec.key_env else ""
        low = detail.lower()
        if code == 401 or (code in (400, 403) and ("api key" in low or "api_key" in low or "unauthorized" in low)):
            if not self.key:
                return AiError(f"{name} needs an API key. Enter one under AI → Settings{where}" + (f"; get one at {self.spec.key_url}." if self.spec.key_url else "."))
            return AiError(f"The {name} API key was rejected (invalid, expired or revoked). Check it under AI → Settings{where}.")
        if code == 403:
            return AiError(f"{name} refused the request (403): the key may not use the model '{self.model}', or the account lacks access. {detail}".strip())
        if code == 404:
            return AiError(f"{name} does not know the model '{self.model}' or the address {_base_of(self.url)} is wrong (404). Check the model and base URL under AI → Settings.")
        if code in (402, 429):
            if self.spec.id == "free":
                return AiError("The free AI allows about one reply every 45 seconds from this server, and it is busy right now. Try again in a minute, "
                               "or pick a provider with your own key (several have free tiers) under AI → Settings.")
            return AiError(f"{name} rate limit or quota reached ({code}). Try again later, or check the plan and billing of the account. {detail}".strip())
        if code == 400:
            return AiError(f"{name} rejected the request (400): {detail or 'bad request'}")
        if code >= 500:
            return AiError(f"{name} had a server error ({code}). Try again in a minute.")
        return AiError(f"{name} returned an error ({code}). {detail}".strip())

    @staticmethod
    def _usage(data: dict) -> Usage:
        u = data.get("usage") or {}
        return Usage(int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0))

    def _message(self, data: dict) -> tuple[dict, str]:
        choices = data.get("choices") or []
        if not choices:
            raise AiError(f"{self.spec.label} returned no answer.")
        return choices[0].get("message") or {}, choices[0].get("finish_reason") or ""

    # --------------------------------------------------------------------- calls
    def structured(self, system, content, schema, effort="medium"):
        instructions = (f"{system}\n\nAnswer with one JSON object only, no prose and no code fence. It must follow this JSON schema:\n"
                        f"{json.dumps(schema.model_json_schema(), separators=(',', ':'))}")
        body = {"messages": [{"role": "system", "content": instructions}, {"role": "user", "content": content}], "response_format": {"type": "json_object"}}
        try:
            data = self._post(body)
        except AiError as error:   # some servers do not support response_format: retry once without it
            if "(400)" not in str(error):
                raise
            body.pop("response_format")
            data = self._post(body)
        message, finish = self._message(data)
        usage = self._usage(data)
        if message.get("refusal"):
            raise RefusedError("The model declined to answer this request.", usage)
        if finish == "length":
            raise AiError("The answer was cut off. Try again with less input, or choose a model with a larger output limit.")
        try:
            parsed = schema.model_validate(extract_json(message.get("content") or ""))
        except ValidationError as error:
            raise AiError("The model's answer did not have the expected fields. Try again, or choose a stronger model under AI → Settings.") from error
        return parsed, data.get("model") or self.model, usage

    def chat(self, system, messages, tools, max_iterations=10):
        convo: list[dict] = [{"role": "system", "content": system}, *messages]
        by_name = {t.__name__: t for t in tools}
        defs = [tool_schema(t) for t in tools]
        usage, model = Usage(), self.model
        for step in range(max_iterations + 1):
            body: dict = {"messages": convo}
            if defs:
                body["tools"] = defs
                body["tool_choice"] = "none" if step == max_iterations else "auto"
            data = self._post(body)
            usage.add(self._usage(data))
            model = data.get("model") or model
            message, _ = self._message(data)
            if message.get("refusal"):
                return Reply("", model, usage, refused=True)
            calls = message.get("tool_calls") or []
            if not calls or step == max_iterations:
                return Reply(_strip_reasoning(message.get("content") or ""), model, usage)
            convo.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})
            for call in calls:
                fn = (call.get("function") or {})
                tool = by_name.get(fn.get("name", ""))
                result = call_tool(tool, fn.get("arguments")) if tool else json.dumps({"error": f"No tool named {fn.get('name')}"})
                convo.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": result})
        return Reply("", model, usage)

    def complete(self, prompt):
        data = self._post({"messages": [{"role": "user", "content": prompt}]})
        message, _ = self._message(data)
        return Reply(_strip_reasoning(message.get("content") or ""), data.get("model") or self.model, self._usage(data))
