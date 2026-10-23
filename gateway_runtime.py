"""Shared Portkey/AIRS Gateway agent runtime used by Trevor Bot and Task."""
import asyncio
import inspect
import json
import math
import os
import traceback
import uuid
from urllib.parse import urlparse

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from portkey_ai import AsyncPortkey

MAX_TURNS = 20
MAX_ATTEMPTS = 1
LOGICAL_MODEL = "bh-ai-gateway"
OBSERVABILITY_VERSION = "r9"
DEFAULT_SYSTEM_PROMPT = ("You are an advanced Security Analyst Agent for Cortex XSIAM. "
                         "Use tools when needed and provide clear, actionable responses.")
MUTATING = {"add_lookup_data", "remove_lookup_data", "create_dataset"}
MUTATION_PREFIXES = ("add_", "remove_", "create_", "delete_", "update_", "set_")
PORTKEY_RESPONSE_HEADERS = {
    "x-portkey-trace-id": "portkey_trace_id",
    "x-portkey-request-id": "portkey_request_id",
    "x-portkey-retry-attempt-count": "retry_attempt_count",
    "x-portkey-cache-status": "cache_status",
    "x-portkey-last-used-option-index": "last_used_option_index",
}


def secret(params, key, default=""):
    value = params.get(key, default)
    return value.get("password", default) if isinstance(value, dict) else value


def enabled(params, key):
    value = params.get(key, False)
    return value if isinstance(value, bool) else str(value).lower() == "true"


def validated_timeout(params, key, default):
    value = params.get(key, default)
    if value in (None, ""):
        value = default
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a finite number between 1 and 300") from exc
    if not math.isfinite(timeout) or not 1 <= timeout <= 300:
        raise ValueError(f"{key} must be a finite number between 1 and 300")
    return timeout


def _requires_https(url, insecure):
    return bool(url) and urlparse(str(url)).scheme.lower() != "https" and not insecure


def validate(params):
    errors = []
    if enabled(params, "ai_gateway_enabled"):
        for key in ("ai_gateway_base_url", "ai_gateway_api_key", "ai_gateway_config"):
            if not secret(params, key):
                errors.append(f"{key} is required when ai_gateway_enabled is true")
        if _requires_https(secret(params, "ai_gateway_base_url"),
                           enabled(params, "ai_gateway_insecure")):
            errors.append("ai_gateway_base_url must use HTTPS unless ai_gateway_insecure is true")
    if enabled(params, "mcp_gateway_enabled"):
        for key in ("mcp_gateway_url", "mcp_gateway_api_key"):
            if not secret(params, key):
                errors.append(f"{key} is required when mcp_gateway_enabled is true")
        if _requires_https(secret(params, "mcp_gateway_url"),
                           enabled(params, "mcp_gateway_insecure")):
            errors.append("mcp_gateway_url must use HTTPS unless mcp_gateway_insecure is true")
    for key in ("ai_gateway_timeout_seconds", "mcp_gateway_timeout_seconds"):
        try:
            validated_timeout(params, key, 60)
        except ValueError as exc:
            errors.append(str(exc))
    try:
        fail_mode(params)
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def fail_mode(params):
    """Return the preserved fail-closed switch. Absent means open."""
    raw = params.get("gateway_fail_mode", "open")
    if raw in (None, ""):
        raw = "open"
    value = str(raw).strip().lower()
    if value not in {"open", "closed"}:
        raise ValueError("gateway_fail_mode must be open or closed")
    return value


class GatewayFailure:
    def __init__(self, kind, status_code, event, allows_fallback, error_type=None):
        self.kind = kind
        self.status_code = status_code
        self.event = event
        self.allows_fallback = allows_fallback
        self.error_type = error_type


_CONNECTION_TYPES = frozenset({
    "APIConnectionError", "ConnectError", "ConnectTimeout", "ConnectTimeoutError",
})


def _exception_chain(exc):
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)


def _status_from(exc):
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status
    status = getattr(exc, "status", None)
    return status if isinstance(status, int) else None


def _hooks_failed_type(exc):
    body = getattr(exc, "body", None)
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if isinstance(error, dict) and error.get("type") == "hooks_failed":
        return "hooks_failed"
    return None


def _stamped_failure(exc):
    kind = getattr(exc, "trevor_failure_class", None)
    if kind not in {"availability", "policy", "client", "unknown"}:
        return None
    return GatewayFailure(
        kind, getattr(exc, "trevor_status_code", None),
        getattr(exc, "trevor_audit_event", None),
        bool(getattr(exc, "trevor_allows_fallback", False)),
        getattr(exc, "trevor_error_type", None))


def gateway_failure_disposition(exc):
    """Classify an AIRS/Portkey failure. Unknown statuses are not availability."""
    stamped = _stamped_failure(exc)
    if stamped is not None:
        return stamped
    status = None
    connection = False
    error_type = None
    for item in _exception_chain(exc):
        if status is None:
            status = _status_from(item)
        if type(item).__name__ in _CONNECTION_TYPES:
            connection = True
        if error_type is None:
            error_type = _hooks_failed_type(item)
    if status == 446:
        return GatewayFailure("policy", 446, "guardrail_denied", False, error_type)
    if status == 412:
        return GatewayFailure("policy", 412, "gateway_budget_exhausted", False)
    if status == 429:
        return GatewayFailure("policy", 429, "gateway_rate_limited", False)
    if status in {401, 403} or (status is not None and 400 <= status < 500 and status != 408):
        return GatewayFailure("client", status, "gateway_client_error", False)
    if status == 408 or (status is not None and status >= 500):
        return GatewayFailure("availability", status, None, False)
    if status is None and connection:
        return GatewayFailure("availability", None, None, True)
    return GatewayFailure("unknown", status, "gateway_unclassified", False)


def stamp_gateway_failure(error, source):
    disposition = gateway_failure_disposition(source)
    error.trevor_failure_class = disposition.kind
    error.trevor_status_code = disposition.status_code
    error.trevor_audit_event = disposition.event
    error.trevor_allows_fallback = disposition.allows_fallback
    error.trevor_error_type = disposition.error_type
    return error


def direct_fallback_allowed(params, exc):
    if fail_mode(params) != "open":
        return False
    if getattr(exc, "trevor_tool_executed", False):
        return False
    return gateway_failure_disposition(exc).allows_fallback


def audit_route_failure(log, route, trace_id, component, params, exc):
    """Record a model or MCP gateway failure. Return whether direct fallback is allowed."""
    mode = fail_mode(params)
    disposition = gateway_failure_disposition(exc)
    tool_executed = bool(getattr(exc, "trevor_tool_executed", False))
    allow = mode == "open" and disposition.allows_fallback and not tool_executed
    fields = {"fail_mode": mode, "failure_class": disposition.kind}
    if disposition.status_code is not None:
        fields["status_code"] = disposition.status_code
    if disposition.error_type:
        fields["error_type"] = disposition.error_type
    if disposition.event:
        audit(log, disposition.event, trace_id, component, **fields)
    if allow:
        audit_exception(log, f"{route}_gateway_fallback", trace_id, component, exc, **fields)
        return True
    if mode == "open":
        refusal = "tool_already_executed" if tool_executed else disposition.kind
        audit_exception(log, f"{route}_gateway_fallback_refused", trace_id, component, exc,
                        refusal_reason=refusal, **fields)
        return False
    closed_event = "model_gateway_failed" if route == "model" else "mcp_selection_failed"
    audit_exception(log, closed_event, trace_id, component, exc, **fields)
    return False


def audit(log, event, trace_id, component, **fields):
    safe = {k: v for k, v in fields.items() if k not in {"prompt", "messages", "api_key"}}
    log(json.dumps({"event": event, "trace_id": trace_id, "component": component, **safe}, sort_keys=True))


def audit_exception(log, event, trace_id, component, exc, **fields):
    """Log exception classes and stack locations without messages or runtime values."""
    root = exc
    seen = set()
    while (getattr(root, "__cause__", None) or getattr(root, "__context__", None)) and id(root) not in seen:
        seen.add(id(root))
        root = getattr(root, "__cause__", None) or getattr(root, "__context__", None)
    frames = traceback.extract_tb(exc.__traceback__)[-12:] if exc.__traceback__ else []
    stack = [f"{os.path.basename(frame.filename)}:{frame.lineno}:{frame.name}" for frame in frames]
    audit(log, event, trace_id, component, reason=type(exc).__name__,
          root_reason=type(root).__name__, stack=stack, **fields)


def attach_diagnostics(exc, trace_id, stage):
    """Attach safe correlation fields for an outer long-running handler."""
    setattr(exc, "trevor_trace_id", trace_id)
    setattr(exc, "trevor_failure_stage", stage)
    return exc


def response_telemetry(response):
    """Extract only documented, non-sensitive Portkey response headers."""
    headers = getattr(response, "_headers", {}) or {}
    lowered = {str(key).lower(): str(value)[:128] for key, value in headers.items()}
    return {field: lowered[header] for header, field in PORTKEY_RESPONSE_HEADERS.items()
            if header in lowered}


def sanitize_schema(schema, defs=None, depth=0, processing=None):
    if not isinstance(schema, dict):
        return schema
    if depth > 10:
        return {"type": "object", "description": "Complex/deeply nested object"}
    processing = processing or set()
    definitions = dict(defs or {})
    definitions.update(schema.get("$defs", {}))
    definitions.update(schema.get("definitions", {}))
    clean = {k: v for k, v in schema.items() if k not in {"$defs", "definitions"}}
    if "$ref" in clean:
        name = clean.pop("$ref").split("/")[-1]
        if name in processing or name not in definitions:
            return {"type": "object", "description": f"Reference to {name}"}
        return sanitize_schema(definitions[name], definitions, depth + 1, processing | {name})
    if any(key in clean for key in ("oneOf", "anyOf", "allOf")):
        return {"type": "object", "description": clean.get("description", "Complex variant type")}
    if "properties" in clean:
        clean["properties"] = {k: sanitize_schema(v, definitions, depth + 1, processing)
                               for k, v in clean["properties"].items()}
    if "items" in clean:
        clean["items"] = sanitize_schema(clean["items"], definitions, depth + 1, processing)
    return clean


def tool_value(tool, key, default=None):
    return tool.get(key, default) if isinstance(tool, dict) else getattr(tool, key, default)


def tool_definitions(discovered, allowlist_text=""):
    """Provider-neutral tool list. OpenAI wire shape is applied only at the Portkey call."""
    allowlist = {x.strip() for x in allowlist_text.split(",") if x.strip()}
    converted = []
    for tool in discovered:
        name = tool_value(tool, "name", "")
        if allowlist and name not in allowlist:
            continue
        schema = tool_value(tool, "inputSchema", tool_value(tool, "parameters", {})) or {}
        converted.append({
            "name": name,
            "description": tool_value(tool, "description", "") or "",
            "parameters": sanitize_schema(dict(schema)),
        })
    return converted


def openai_tools_payload(definitions):
    return [{"type": "function", "function": {
        "name": item.get("name", ""),
        "description": item.get("description", "") or "",
        "parameters": item.get("parameters") or {},
    }} for item in definitions or []]


def normalized_tool_call(call):
    if isinstance(call, dict):
        function = call.get("function") or {}
        return {"id": call.get("id"), "name": function.get("name"),
                "arguments": function.get("arguments")}
    function = getattr(call, "function", None)
    return {"id": getattr(call, "id", None), "name": getattr(function, "name", None),
            "arguments": getattr(function, "arguments", None)}


def authorized_tool_caller(caller, advertised_names):
    allowed = frozenset(advertised_names)

    async def call(name, arguments, *args, **kwargs):
        if name not in allowed:
            raise PermissionError("tool_not_advertised")
        return await caller(name, arguments, *args, **kwargs)

    return call


def is_mutating(name):
    return name in MUTATING or name.startswith(MUTATION_PREFIXES)


def _factory(insecure, headers):
    def make(**kwargs):
        kwargs["verify"] = not insecure
        if headers:
            kwargs["headers"] = {**kwargs.get("headers", {}), **headers}
        return httpx.AsyncClient(**kwargs)
    return make


class MCPConnection:
    def __init__(self, url, token, insecure=False, headers=None, timeout_seconds=60):
        self.url = url
        self.token = token
        self.insecure = insecure
        self.headers = headers
        self.timeout_seconds = float(timeout_seconds)
        self.client = self._new_client()

    def _new_client(self):
        transport = StreamableHttpTransport(
            url=self.url, httpx_client_factory=_factory(self.insecure, self.headers))
        return Client(transport, auth=None if self.headers else self.token,
                      timeout=self.timeout_seconds)

    async def open(self):
        await asyncio.wait_for(self.client.__aenter__(), timeout=self.timeout_seconds)
        return self

    async def close(self):
        await asyncio.wait_for(
            self.client.__aexit__(None, None, None), timeout=self.timeout_seconds)

    async def list_tools(self):
        return await asyncio.wait_for(
            self.client.list_tools(), timeout=self.timeout_seconds)

    async def call_tool(self, name, arguments, headers=None):
        invocation_headers = {**(self.headers or {}), **(headers or {})}
        invocation = MCPConnection(
            self.url, self.token, self.insecure, invocation_headers,
            self.timeout_seconds)
        await invocation.open()
        try:
            return await asyncio.wait_for(
                invocation.client.call_tool(name, arguments, raise_on_error=False),
                timeout=self.timeout_seconds)
        finally:
            try:
                await invocation.close()
            except Exception:
                pass


async def connect_mcp(params, trace_id, metadata, log, component):
    if not enabled(params, "mcp_gateway_enabled"):
        direct = (params.get("mcp_url") or params.get("mcp_uri"),
                  secret(params, "mcp_auth_token") or secret(params, "mcp_api_key"))
        insecure = enabled(params, "mcp_insecure") or enabled(params, "insecure")
        timeout_seconds = validated_timeout(
            params, "mcp_gateway_timeout_seconds", 60)
        connection = await MCPConnection(
            *direct, insecure, timeout_seconds=timeout_seconds).open()
        try:
            return connection, False, await connection.list_tools()
        except Exception:
            try:
                await connection.close()
            except Exception:
                pass
            raise
    insecure = enabled(params, "mcp_gateway_insecure")
    timeout_seconds = validated_timeout(params, "mcp_gateway_timeout_seconds", 60)
    headers = {"x-portkey-api-key": secret(params, "mcp_gateway_api_key"),
               "x-portkey-trace-id": trace_id,
               "x-portkey-span-id": uuid.uuid4().hex[:16],
               "x-portkey-span-name": f"{component}-mcp-discovery",
               "x-trace-id": trace_id,
               "x-request-id": metadata.get("request_id", trace_id),
               "x-user-id": metadata.get("slack_user_id", metadata.get("_user", "")),
               "x-portkey-metadata": json.dumps(metadata, separators=(",", ":"))}
    gateway = MCPConnection(params["mcp_gateway_url"], None, insecure, headers,
                            timeout_seconds=timeout_seconds)
    try:
        await gateway.open()
        tools = await gateway.list_tools()
        return gateway, True, tools
    except Exception as exc:
        try:
            await gateway.close()
        except Exception:
            pass
        error = RuntimeError("MCP Gateway unavailable")
        stamp_gateway_failure(error, exc)
        raise error from exc


def mcp_tool_headers(trace_id, metadata, component, name, parent_span_id=""):
    safe_name = "".join(
        char if char.isalnum() or char == "-" else "-" for char in str(name)
    )[:64]
    headers = {
        "x-portkey-trace-id": trace_id,
        "x-portkey-span-id": uuid.uuid4().hex[:16],
        "x-portkey-span-name": "{}-mcp-tool-{}".format(
            component or "trevor", safe_name),
        "x-trace-id": trace_id,
        "x-request-id": str((metadata or {}).get("request_id") or trace_id),
        "x-portkey-metadata": json.dumps(
            metadata or {}, separators=(",", ":")),
    }
    if parent_span_id:
        headers["x-portkey-parent-span-id"] = parent_span_id
    return headers


async def call_tool_with_safe_fallback(mcp, via_gateway, direct_factory, name, arguments,
                                       log=None, trace_id="", component="", timeout_seconds=60,
                                       metadata=None, parent_span_id=""):
    """Invoke only the selected MCP route; direct factories are intentionally unused."""
    headers = (mcp_tool_headers(
        trace_id, metadata, component, name, parent_span_id)
        if via_gateway else None)
    try:
        accepts_headers = len(inspect.signature(mcp.call_tool).parameters) >= 3
    except (TypeError, ValueError):
        accepts_headers = False
    call = (mcp.call_tool(name, arguments, headers)
            if headers is not None and accepts_headers
            else mcp.call_tool(name, arguments))
    result = await asyncio.wait_for(call, timeout=float(timeout_seconds))
    is_error = bool(getattr(result, "isError", False) or
                    getattr(result, "is_error", False))
    error_text = str(getattr(result, "content", "")).lower() if is_error else ""
    if via_gateway and any(marker in error_text for marker in (
            "downstream not connected", "client is not connected", "session terminated")):
        if log:
            audit(log, "mcp_downstream_disconnected", trace_id, component or "trevor")
        raise RuntimeError("MCP gateway downstream is disconnected")
    if is_error and log:
        audit(log, "mcp_tool_error", trace_id, component or "trevor", tool=name)
    return result


def _response_status(response):
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status
    for attr in ("http_response", "response"):
        raw = getattr(response, attr, None)
        status = getattr(raw, "status_code", None)
        if isinstance(status, int):
            return status
    return None


def _hook_results(response):
    direct = getattr(response, "hook_results", None)
    if isinstance(direct, dict):
        return direct
    extra = getattr(response, "model_extra", None)
    if isinstance(extra, dict) and isinstance(extra.get("hook_results"), dict):
        return extra["hook_results"]
    return None


def guardrail_flag_status(response):
    """Return 246 when a synchronous guardrail failed but the completion was allowed."""
    if _response_status(response) == 246:
        return 246
    hooks = _hook_results(response)
    if not isinstance(hooks, dict):
        return None
    for key in ("before_request_hooks", "after_request_hooks"):
        entries = hooks.get(key) or []
        if any(isinstance(item, dict) and item.get("verdict") is False for item in entries):
            return 246
    return None


def assistant_message_payload(message):
    if hasattr(message, "model_dump"):
        payload = message.model_dump(exclude_none=True)
    elif hasattr(message, "to_dict"):
        payload = message.to_dict()
    else:
        payload = {"content": getattr(message, "content", None)}
    payload["role"] = "assistant"
    return payload


async def run_portkey(prompt, params, mcp, tools, metadata, trace_id, tool_caller=None,
                      log=None, component="", system_prompt=None):
    client = AsyncPortkey(api_key=secret(params, "ai_gateway_api_key"),
                          base_url=params["ai_gateway_base_url"],
                          config=params["ai_gateway_config"], trace_id=trace_id,
                          metadata=metadata, strict_open_ai_compliance=False)
    messages = [{"role": "system", "content": system_prompt or DEFAULT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}]
    executed = False
    response_received = False
    advertised_names = {str(item.get("name") or "") for item in (tools or [])
                        if isinstance(item, dict)}
    wire_tools = openai_tools_payload(tools)
    for turn_index in range(MAX_TURNS):
        response = None
        span_id = uuid.uuid4().hex[:16]
        span_name = f"{component or 'trevor'}-model-turn-{turn_index + 1}"
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = await client.chat.completions.create(
                    model=LOGICAL_MODEL, messages=messages,
                    tools=wire_tools or None,
                    timeout=validated_timeout(params, "ai_gateway_timeout_seconds", 60),
                    extra_headers={"x-portkey-span-id": span_id,
                                   "x-portkey-span-name": span_name})
                response_received = True
                flagged = guardrail_flag_status(response)
                if log and flagged is not None:
                    audit(log, "guardrail_flagged", trace_id, component or "trevor",
                          status_code=flagged, fail_mode=fail_mode(params))
                if log:
                    audit(log, "model_gateway_completed", trace_id, component or "trevor",
                          span_id=span_id, span_name=span_name, turn=turn_index + 1,
                          config_id=str(params.get("ai_gateway_config") or "")[:128],
                          logical_model=LOGICAL_MODEL,
                          **response_telemetry(response))
                break
            except Exception as exc:
                if attempt + 1 == MAX_ATTEMPTS:
                    error = RuntimeError("AI Gateway unavailable")
                    setattr(error, "trevor_model_response_received", response_received)
                    setattr(error, "trevor_tool_executed", executed)
                    stamp_gateway_failure(error, exc)
                    raise error from exc
                await asyncio.sleep(min(2 ** attempt, 4))
        try:
            message = response.choices[0].message
        except Exception as exc:
            setattr(exc, "trevor_model_response_received", response_received)
            setattr(exc, "trevor_tool_executed", executed)
            raise
        calls = getattr(message, "tool_calls", None) or []
        if not calls:
            return message.content or ""
        messages.append(assistant_message_payload(message))
        for call in calls:
            normalized = normalized_tool_call(call)
            try:
                raw_arguments = normalized["arguments"]
                args = raw_arguments if isinstance(raw_arguments, dict) else json.loads(raw_arguments or "{}")
                if not isinstance(args, dict):
                    raise ValueError("tool arguments must be a JSON object")
                if normalized["name"] not in advertised_names:
                    raise PermissionError("tool_not_advertised")
                # Record the attempt before invoking the tool. A failed invocation must
                # still prevent a second model-agent run from replaying the operation.
                executed = True
                caller = tool_caller or mcp.call_tool
                try:
                    accepts_parent = len(inspect.signature(caller).parameters) >= 3
                except (TypeError, ValueError):
                    accepts_parent = False
                result = await (caller(normalized["name"], args, span_id)
                                if accepts_parent
                                else caller(normalized["name"], args))
                content = str(getattr(result, "content", result))
            except Exception as exc:
                content = json.dumps({"error": ("tool_not_authorized" if isinstance(exc, PermissionError) else "tool_execution_failed"), "exception": type(exc).__name__})
            messages.append({"role": "tool", "tool_call_id": normalized["id"],
                             "name": normalized["name"], "content": content})
    error = RuntimeError(f"Agent exceeded the {MAX_TURNS}-turn limit")
    setattr(error, "trevor_model_response_received", response_received)
    setattr(error, "trevor_tool_executed", executed)
    raise error


def new_trace(component, metadata=None):
    enriched = {
        "_environment": "dev",
        "environment": "dev",
        "component": component,
        "feature": "automation-agent" if component == "trevor-task" else "slack-agent",
        "version": OBSERVABILITY_VERSION,
        **(metadata or {}),
    }
    supplied_trace_id = str(enriched.pop("_trevor_trace_id", "") or "")
    trace_id = supplied_trace_id or str(uuid.uuid4())
    slack_user_id = str(enriched.get("slack_user_id") or "")
    slack_user_name = str(enriched.get("slack_user_name") or "")
    if slack_user_name or slack_user_id:
        enriched["_user"] = (slack_user_name or slack_user_id)[:128]
    request_id = str(enriched.get("request_id") or trace_id)
    if request_id:
        enriched["request_id"] = request_id
    workspace = str(
        enriched.get("workspace_id") or enriched.get("slack_workspace_id") or "")
    if workspace:
        enriched["workspace_id"] = workspace
    if not enriched.get("session_id"):
        channel = str(enriched.get("slack_channel_id") or "")
        thread = str(enriched.get("slack_thread_id") or "")
        if channel:
            enriched["session_id"] = ":".join(
                value for value in (workspace, channel, thread or channel)
                if value)
    if enriched.get("session_id") and not enriched.get("conversation_id"):
        enriched["conversation_id"] = enriched["session_id"]
    return trace_id, {
        str(key): str(value)[:128] for key, value in enriched.items()}
