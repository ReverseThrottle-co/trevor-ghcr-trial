"""Gateway adapter kept separate so disabled mode remains the production Bot path."""
import asyncio
import json
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from gateway_runtime import (attach_diagnostics, audit, audit_exception,
                             audit_route_failure, authorized_tool_caller,
                             call_tool_with_safe_fallback, connect_mcp, enabled,
                             new_trace, run_portkey, secret, tool_definitions,
                             validate, validated_timeout)

def _format_history(history):
    lines = []
    for item in history or []:
        if not isinstance(item, dict):
            continue
        role = "assistant" if item.get("is_bot") else "user"
        name = item.get("user_name") or ("Trevor" if role == "assistant" else "Slack user")
        content = re.sub(r"<@[A-Z0-9]+>", "", str(item.get("text") or "")).strip()
        file_reference = str(item.get("file") or "").strip()
        if file_reference:
            content = f"{content}\nAttached file: {file_reference}".strip()
        if content:
            lines.append(f"{role} ({name}): {content}")
    return "\n".join(lines)


def without_current_message(messages, current_ts):
    """Remove the triggering Slack message before building model history."""
    if not current_ts:
        return list(messages or [])
    return [message for message in (messages or [])
            if message.get("ts") != current_ts]


def vertex_credentials(params):
    """Parse encrypted Bot Vertex credentials for the gateway-disabled direct path."""
    raw = secret(params, "google_creds_json")
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("google_creds_json is not valid JSON") from exc
    if not isinstance(value, dict) or not value.get("project_id"):
        raise ValueError("google_creds_json must contain a project_id")
    return value


async def _connect_with_fallback(params, trace_id, metadata, log, component):
    try:
        return await connect_mcp(params, trace_id, metadata, log, component)
    except Exception as exc:
        if not enabled(params, "mcp_gateway_enabled"):
            audit_exception(log, "mcp_selection_failed", trace_id, component, exc)
            raise
        if not audit_route_failure(log, "mcp", trace_id, component, params, exc):
            raise
        direct_params = dict(params)
        direct_params["mcp_gateway_enabled"] = False
        try:
            return await connect_mcp(direct_params, trace_id, metadata, log, component)
        except Exception as direct_exc:
            audit_exception(log, "direct_mcp_fallback_failed", trace_id, component, direct_exc)
            raise


async def _run(prompt, history, params, metadata, log, direct_runner, system_prompt=None):
    errors = validate(params)
    if errors:
        raise ValueError("; ".join(errors))
    if not enabled(params, "ai_gateway_enabled") and not enabled(params, "mcp_gateway_enabled"):
        return await direct_runner(prompt, history, None, None, None)
    metadata = dict(metadata or {})
    environment = params.get("environment")
    if environment not in (None, ""):
        metadata["environment"] = environment
    trace_id, metadata = new_trace("trevor-bot", metadata)
    try:
        mcp, via_gateway, listed = await _connect_with_fallback(
            params, trace_id, metadata, log, "bot")
    except Exception as exc:
        error = RuntimeError("mcp_connectivity_failed")
        raise attach_diagnostics(error, trace_id, "mcp_selection") from exc
    try:
        tools = tool_definitions(listed if isinstance(listed, list) else listed.tools,
                                 params.get("mcp_tool_allowlist") or "")
        context = _format_history(history)
        combined = f"Conversation history:\n{context}\n\nCurrent request:\n{prompt}" if context else prompt
        mcp_timeout_seconds = validated_timeout(
            params, "mcp_gateway_timeout_seconds", 60)

        async def invoke_tool(name, arguments, parent_span_id=""):
            return await call_tool_with_safe_fallback(
                mcp, via_gateway, None, name, arguments,
                log=log, trace_id=trace_id, component="bot",
                timeout_seconds=mcp_timeout_seconds,
                metadata=metadata, parent_span_id=parent_span_id)
        tool_caller = authorized_tool_caller(
            invoke_tool, {item["name"] for item in tools})
        if enabled(params, "ai_gateway_enabled"):
            try:
                return await run_portkey(combined, params, mcp, tools, metadata,
                                         trace_id, tool_caller=tool_caller,
                                         log=log, component="bot",
                                         system_prompt=system_prompt)
            except Exception as exc:
                if not audit_route_failure(log, "model", trace_id, "bot", params, exc):
                    error = RuntimeError("AI Gateway unavailable")
                    raise attach_diagnostics(error, trace_id, "model_gateway") from exc
                try:
                    return await direct_runner(combined, history, mcp, tools, tool_caller)
                except Exception as direct_exc:
                    audit_exception(log, "direct_model_fallback_failed", trace_id, "bot", direct_exc)
                    error = RuntimeError("direct_model_failed")
                    raise attach_diagnostics(error, trace_id, "direct_model") from direct_exc
        try:
            return await direct_runner(combined, history, mcp, tools, tool_caller)
        except Exception as exc:
            audit_exception(log, "direct_model_failed", trace_id, "bot", exc)
            error = RuntimeError("direct_model_failed")
            raise attach_diagnostics(error, trace_id, "direct_model") from exc
    finally:
        try:
            await mcp.close()
        except Exception as exc:
            audit(log, "mcp_close_error", trace_id, "bot", reason=type(exc).__name__)

def gateway_response(prompt, history, params, metadata, log, direct_runner, system_prompt=None):
    return asyncio.run(_run(prompt, history, params, metadata, log, direct_runner,
                            system_prompt))
