"""Persistent local conversation store for the grounded assistant."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

from .schemas import AssistantCitationView, AssistantMessageView


class ConversationNotFound(Exception):
    pass


class LocalConversationStore:
    """Durable JSON store; no browser-only state or remote chat retention."""

    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve()
        self._path = self._root / "conversations.json"
        self._lock = RLock()
        self._root.mkdir(parents=True, exist_ok=True)

    def create(self, first_message: str) -> dict[str, object]:
        with self._lock:
            catalog = self._read()
            now = datetime.now(UTC).isoformat()
            conversation = {
                "id": str(uuid4()),
                "title": self._title(first_message),
                "created_at": now,
                "updated_at": now,
                "pinned": False,
                "memory_summary": "尚未形成长期记忆。",
                "summary": "新的安全咨询",
                "messages": [],
            }
            catalog["conversations"].append(conversation)
            self._write(catalog)
            return dict(conversation)

    def get(self, conversation_id: UUID) -> dict[str, object]:
        with self._lock:
            for item in self._read()["conversations"]:
                if item.get("id") == str(conversation_id):
                    return dict(item)
        raise ConversationNotFound(str(conversation_id))

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            rows = list(self._read()["conversations"])
        return sorted(
            rows,
            key=lambda item: (bool(item.get("pinned", False)), str(item.get("updated_at", ""))),
            reverse=True,
        )

    def append(
        self,
        conversation_id: UUID,
        *,
        role: str,
        content: str,
        citations: list[AssistantCitationView] | None = None,
        model: str | None = None,
    ) -> dict[str, object]:
        with self._lock:
            catalog = self._read()
            for conversation in catalog["conversations"]:
                if conversation.get("id") != str(conversation_id):
                    continue
                messages = conversation.setdefault("messages", [])
                assert isinstance(messages, list)
                messages.append(
                    {
                        "id": str(uuid4()),
                        "role": role,
                        "content": content,
                        "citations": [item.model_dump(mode="json") for item in citations or []],
                        "model": model,
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                )
                conversation["updated_at"] = datetime.now(UTC).isoformat()
                conversation["memory_summary"] = self._memory(messages)
                self._write(catalog)
                return dict(conversation)
        raise ConversationNotFound(str(conversation_id))

    def set_summary(self, conversation_id: UUID, summary: str) -> dict[str, object]:
        with self._lock:
            catalog = self._read()
            for conversation in catalog["conversations"]:
                if conversation.get("id") == str(conversation_id):
                    conversation["summary"] = summary.strip()[:80] or "新的安全咨询"
                    self._write(catalog)
                    return dict(conversation)
        raise ConversationNotFound(str(conversation_id))

    def rename(self, conversation_id: UUID, title: str) -> dict[str, object]:
        normalized = title.replace("\n", " ").strip()[:80]
        if not normalized:
            raise ValueError("conversation title must not be blank")
        with self._lock:
            catalog = self._read()
            for conversation in catalog["conversations"]:
                if conversation.get("id") == str(conversation_id):
                    conversation["title"] = normalized
                    conversation["summary"] = normalized
                    conversation["updated_at"] = datetime.now(UTC).isoformat()
                    self._write(catalog)
                    return dict(conversation)
        raise ConversationNotFound(str(conversation_id))

    def set_pinned(self, conversation_id: UUID, pinned: bool) -> dict[str, object]:
        with self._lock:
            catalog = self._read()
            for conversation in catalog["conversations"]:
                if conversation.get("id") == str(conversation_id):
                    conversation["pinned"] = bool(pinned)
                    conversation["updated_at"] = datetime.now(UTC).isoformat()
                    self._write(catalog)
                    return dict(conversation)
        raise ConversationNotFound(str(conversation_id))

    def delete(self, conversation_id: UUID) -> None:
        with self._lock:
            catalog = self._read()
            original = len(catalog["conversations"])
            catalog["conversations"] = [
                item for item in catalog["conversations"] if item.get("id") != str(conversation_id)
            ]
            if len(catalog["conversations"]) == original:
                raise ConversationNotFound(str(conversation_id))
            self._write(catalog)

    @staticmethod
    def messages(conversation: dict[str, object]) -> list[AssistantMessageView]:
        raw = conversation.get("messages", [])
        return [AssistantMessageView.model_validate(item) for item in raw if isinstance(item, dict)]

    def _read(self) -> dict[str, list[dict[str, object]]]:
        if not self._path.is_file():
            return {"conversations": []}
        try:
            value = json.loads(self._path.read_text(encoding="utf-8"))
            rows = value.get("conversations", []) if isinstance(value, dict) else []
            return {"conversations": [item for item in rows if isinstance(item, dict)]}
        except (OSError, ValueError):
            return {"conversations": []}

    def _write(self, catalog: dict[str, object]) -> None:
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self._path)

    @staticmethod
    def _title(message: str) -> str:
        return message.replace("\n", " ").strip()[:32] or "新对话"

    @staticmethod
    def _memory(messages: list[object]) -> str:
        users = [
            str(item.get("content", "")).replace("\n", " ").strip()[:90]
            for item in messages
            if isinstance(item, dict) and item.get("role") == "user"
        ]
        sources = [
            str(citation.get("document_title", ""))
            for item in messages
            if isinstance(item, dict)
            for citation in item.get("citations", [])
            if isinstance(citation, dict) and citation.get("document_title")
        ]
        focus = "；".join(users[-4:]) or "尚未形成长期记忆。"
        documents = "、".join(dict.fromkeys(sources[-4:]))
        return f"近期关注：{focus}" + (f"。已参考：{documents}" if documents else "")
