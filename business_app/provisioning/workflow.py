"""Idempotent, developer-approved provisioning workflow.

Secrets are accepted only in memory and are never written to workflow state.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from contextlib import contextmanager
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from werkzeug.security import generate_password_hash

from business_app.export_starter import export_starter
from .providers import GitHubProvider, NeonProvider, RenderProvider
from .providers.http import ProviderError, ProviderHTTPError, ProviderOperationUnknown


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class WorkflowStateStore:
    """Persist secret-free workflow state in Neon when configured, else use private local files."""

    def __init__(self, root=None, database_url=None):
        self.database_url = (database_url or os.getenv("DATABASE_URL", "")).strip() or None
        self.root = None
        if not self.database_url:
            self.root = Path(root or Path.home() / ".business-app-provisioner" / "runs").expanduser()
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.root, 0o700)
            except OSError:
                pass

    def _connect(self):
        import psycopg
        database_url = self.database_url
        if database_url.startswith("postgres://"):
            database_url = "postgresql://" + database_url[len("postgres://"):]
        return psycopg.connect(database_url, connect_timeout=8)

    @staticmethod
    def _ensure_schema(connection):
        connection.execute("""
            CREATE TABLE IF NOT EXISTS provisioning_workflow_state (
                workflow_id TEXT PRIMARY KEY, plan_id TEXT, business_slug TEXT,
                status TEXT, step TEXT, state JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), error TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS provisioning_audit_events (
                id BIGSERIAL PRIMARY KEY, event VARCHAR(64) NOT NULL,
                actor VARCHAR(64) NOT NULL DEFAULT 'developer',
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS ix_provisioning_audit_created_at
            ON provisioning_audit_events (created_at DESC)
        """)

    def check_connection(self):
        if not self.database_url:
            return True
        with self._connect() as connection:
            self._ensure_schema(connection)
            connection.execute("SELECT 1")
        return True

    def check_round_trip(self):
        """Verify durable JSONB write/read/delete using a unique temporary record."""
        if not self.database_url:
            raise RuntimeError("PostgreSQL is not configured for persistent workflow storage")
        workflow_id = "storage-check-" + secrets.token_hex(12)
        state = {
            "plan_id": workflow_id,
            "business_slug": "storage-check",
            "status": "diagnostic",
            "step": "storage_check",
            "resources": {},
            "history": [],
            "error": None,
        }
        safe_state, serialized = self._safe_state(workflow_id, state)
        with self._connect() as connection:
            self._ensure_schema(connection)
            connection.execute("""
                INSERT INTO provisioning_workflow_state
                    (workflow_id, plan_id, business_slug, status, step, state, updated_at, error)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, NOW(), %s)
            """, (
                workflow_id, safe_state["plan_id"], safe_state["business_slug"],
                safe_state["status"], safe_state["step"], serialized, safe_state["error"],
            ))
            row = connection.execute(
                "SELECT state::text FROM provisioning_workflow_state WHERE workflow_id = %s",
                (workflow_id,),
            ).fetchone()
            if not row:
                raise RuntimeError("Persistent workflow state could not be read after writing")
            restored = json.loads(row[0])
            if restored.get("workflow_id") != workflow_id or restored.get("status") != "diagnostic":
                raise RuntimeError("Persistent workflow state did not match the diagnostic record")
            connection.execute(
                "DELETE FROM provisioning_workflow_state WHERE workflow_id = %s",
                (workflow_id,),
            )
        return True

    def append_audit_event(self, event, actor, details):
        if not self.database_url:
            raise RuntimeError("PostgreSQL is not configured for persistent audit storage")
        allowed = {"provider", "connected", "plan_id", "business_slug", "status", "step", "reason"}
        safe_details = {
            key: value for key, value in details.items()
            if key in allowed and isinstance(value, (str, int, float, bool, type(None)))
        }
        with self._connect() as connection:
            self._ensure_schema(connection)
            connection.execute(
                "INSERT INTO provisioning_audit_events (event, actor, details) VALUES (%s, %s, %s::jsonb)",
                (str(event)[:64], str(actor)[:64], json.dumps(safe_details, ensure_ascii=False)),
            )

    def path_for(self, workflow_id):
        if not workflow_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in workflow_id):
            raise ValueError("Invalid workflow identifier")
        if self.root is None:
            raise RuntimeError("File paths are unavailable when PostgreSQL persistence is enabled")
        return self.root / f"{workflow_id}.json"

    @contextmanager
    def claim(self, workflow_id):
        """Acquire an exclusive per-workflow execution claim across workers/processes."""
        if not workflow_id or any(
            ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for ch in workflow_id
        ):
            raise ValueError("Invalid workflow identifier")

        if self.database_url:
            connection = self._connect()
            connection.autocommit = True
            acquired = False
            try:
                row = connection.execute(
                    "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                    (workflow_id,),
                ).fetchone()
                acquired = bool(row and row[0])
                if not acquired:
                    raise ProviderError(
                        "This provisioning workflow is already running in another worker"
                    )
                yield
            finally:
                if acquired:
                    try:
                        connection.execute(
                            "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                            (workflow_id,),
                        )
                    except Exception:
                        # Closing the PostgreSQL session releases any session-level
                        # advisory lock even if explicit unlock fails.
                        pass
                connection.close()
            return

        lock_path = self.path_for(workflow_id).with_suffix(".lock")
        handle = open(lock_path, "a+b")
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                except OSError:
                    raise ProviderError(
                        "This provisioning workflow is already running in another process"
                    ) from None
            else:
                import fcntl
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    raise ProviderError(
                        "This provisioning workflow is already running in another process"
                    ) from None
            yield
        finally:
            if locked:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    @staticmethod
    def _safe_state(workflow_id, state):
        provisioning_marker = state.get("provisioning_marker")
        if provisioning_marker is not None and not re.fullmatch(r"[a-f0-9]{32}", str(provisioning_marker)):
            raise ValueError("Refusing to persist an invalid provisioning recovery marker")
        resource_operations = state.get("resource_operations", {})
        if not isinstance(resource_operations, dict):
            raise ValueError("Refusing to persist invalid provisioning recovery operations")
        safe_operations = {}
        allowed_steps = {"github_repository", "neon_project", "render_service"}
        allowed_statuses = {"intent", "unknown", "reconciling", "completed", "failed"}
        for step, operation in resource_operations.items():
            if step not in allowed_steps or not isinstance(operation, dict):
                raise ValueError("Refusing to persist invalid provisioning recovery operations")
            if operation.get("status") not in allowed_statuses:
                raise ValueError("Refusing to persist invalid provisioning recovery operation status")
            marker = operation.get("marker")
            if marker is not None and not re.fullmatch(r"[a-f0-9]{32}", str(marker)):
                raise ValueError("Refusing to persist an invalid operation recovery marker")
            safe_operation = {
                key: operation[key]
                for key in (
                    "provider", "resource_name", "marker", "status",
                    "updated_at", "resource_id", "last_error_code",
                )
                if key in operation
            }
            safe_operations[step] = safe_operation
        safe_state = {
            "workflow_id": workflow_id, "plan_id": state.get("plan_id"),
            "business_slug": state.get("business_slug"),
            "business_name": str(state.get("business_name") or state.get("business_slug") or "")[:200],
            "modules": [str(item)[:80] for item in state.get("modules", []) if isinstance(item, str)][:20],
            "status": state.get("status"),
            "step": state.get("step"), "resources": state.get("resources", {}),
            "resource_operations": safe_operations,
            "provisioning_marker": provisioning_marker,
            "history": state.get("history", []), "updated_at": _utc_now(),
            "error": state.get("error"),
        }
        serialized = json.dumps(safe_state, ensure_ascii=False, separators=(",", ":"))
        forbidden_markers = (
            "DATABASE_URL", "ADMIN_PASSWORD", "SECRET_KEY", "NEON_API_KEY",
            "GITHUB_TOKEN", "RENDER_API_KEY", "AUTHORIZATION", "PRIVATE_KEY",
            "CONNECTION_URI", "API_TOKEN",
        )
        if any(marker in serialized.upper() for marker in forbidden_markers):
            raise ValueError("Refusing to persist provisioning state containing a secret marker")
        if re.search(r"(?i)(?:postgres(?:ql)?://|bearer\s+|gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|(?:pbkdf2|scrypt):)", serialized):
            raise ValueError("Refusing to persist provisioning state containing a credential or connection string")
        return safe_state, serialized

    def load(self, workflow_id):
        if self.database_url:
            if not workflow_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in workflow_id):
                raise ValueError("Invalid workflow identifier")
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT state::text FROM provisioning_workflow_state WHERE workflow_id = %s",
                    (workflow_id,),
                ).fetchone()
            return json.loads(row[0]) if row else None
        path = self.path_for(workflow_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, workflow_id, state):
        safe_state, serialized = self._safe_state(workflow_id, state)
        if self.database_url:
            with self._connect() as connection:
                self._ensure_schema(connection)
                connection.execute("""
                    INSERT INTO provisioning_workflow_state
                        (workflow_id, plan_id, business_slug, status, step, state, updated_at, error)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb, NOW(), %s)
                    ON CONFLICT (workflow_id) DO UPDATE SET
                        plan_id = EXCLUDED.plan_id, business_slug = EXCLUDED.business_slug,
                        status = EXCLUDED.status, step = EXCLUDED.step, state = EXCLUDED.state,
                        updated_at = NOW(), error = EXCLUDED.error
                """, (
                    workflow_id, safe_state.get("plan_id"), safe_state.get("business_slug"),
                    safe_state.get("status"), safe_state.get("step"), serialized,
                    safe_state.get("error"),
                ))
            return workflow_id
        path = self.path_for(workflow_id)
        serialized = json.dumps(safe_state, ensure_ascii=False, indent=2) + "\n"
        handle, temp_name = tempfile.mkstemp(prefix=f".{workflow_id}-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temp_name, 0o600)
            except OSError:
                pass
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return path


class ProvisioningWorkflow:
    """Create a clean customer app in isolated GitHub, Neon and Render resources."""

    def __init__(self, *, github=None, neon=None, render=None, state_store=None,
                 health_checker=None, sleep=time.sleep, health_timeout=600, health_interval=10):
        self.github = github or GitHubProvider()
        self.neon = neon or NeonProvider()
        self.render = render or RenderProvider()
        self.state_store = state_store
        self.health_checker = health_checker or self._http_health_check
        self.sleep = sleep
        self.health_timeout = health_timeout
        self.health_interval = health_interval

    @staticmethod
    def _http_health_check(url, timeout=10):
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "business-app-provisioner/1.0"})
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.status == 200
        except (HTTPError, URLError, TimeoutError, OSError):
            return False

    def _wait_for_health(self, service, workflow_url=None):
        details = service.get("serviceDetails") or {}
        url = details.get("url") or service.get("url") or workflow_url
        if not url:
            raise ProviderError("Render did not return a public service URL; deployment health cannot be verified")
        health_url = url.rstrip("/") + "/health"
        deadline = time.monotonic() + self.health_timeout
        while True:
            if self.health_checker(health_url):
                return health_url
            if time.monotonic() >= deadline:
                raise ProviderError("Render service did not pass its /health check before the timeout")
            self.sleep(self.health_interval)

    @staticmethod
    def _normalize_repository_url(value):
        return (value or "").strip().rstrip("/").removesuffix(".git").casefold()

    def _require_customer_owned_connections(self, plan):
        """Reject customer-owned plans unless every adapter carries this customer's verified scope."""
        if plan.get("ownership_mode", "managed") != "customer_owned":
            return
        slug = ((plan.get("business") or {}).get("slug") or "")
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
            raise ProviderError("Customer-owned provisioning requires a valid customer scope")
        for name, provider in (("GitHub", self.github), ("Neon", self.neon), ("Render", self.render)):
            if (
                getattr(provider, "_business_studio_customer_id", None) != slug
                or getattr(provider, "_business_studio_verified_connection", False) is not True
            ):
                raise ProviderError(
                    f"Customer-owned provisioning requires a verified {name} connection for this exact customer. "
                    "No developer credentials were used; the wizard will not fall back to developer account credentials."
                )

    def _check_customer_owned_provider_identity(self, plan, *, github_owner, connections=None):
        """Revalidate live provider credentials and exact customer targets immediately before writes."""
        if plan.get("ownership_mode", "managed") != "customer_owned":
            return {}
        if connections is None:
            connections = {
                "github": self.github.check_connection(),
                "neon": self.neon.check_connection(),
                "render": self.render.check_connection(),
            }
        for provider_name, result in connections.items():
            if not isinstance(result, dict) or result.get("connected") is not True:
                raise ProviderError(f"{provider_name.title()} connection could not be verified")
        if connections["render"].get("workspace_selected") is not True:
            raise ProviderError("Render did not verify access to the selected workspace")
        connected_github_account = connections["github"].get("account")
        if (
            not isinstance(connected_github_account, str)
            or not isinstance(github_owner, str)
            or connected_github_account.casefold() != github_owner.casefold()
        ):
            raise ProviderError("GitHub authenticated account does not match the customer-owned repository target")
        return connections

    def preflight(self, plan, *, github_owner, known_resources=None,
                  provisioning_marker=None, pending_operations=None):
        """Inspect provider access and require identity matches for previously created resources."""
        if not isinstance(plan, dict) or plan.get("mode") != "dry_run":
            raise ProviderError("Preflight requires a dry-run provisioning plan")
        self._require_customer_owned_connections(plan)
        self._check_customer_owned_provider_identity(plan, github_owner=github_owner)
        business = plan.get("business") or {}
        slug = business.get("slug")
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
            raise ProviderError("Provisioning plan is missing a valid business slug")
        if known_resources is None:
            known_resources = {}
            plan_id = plan.get("plan_id")
            if isinstance(plan_id, str) and re.fullmatch(r"[a-f0-9]{20}", plan_id):
                database_url = os.getenv("DATABASE_URL", "").strip()
                if database_url:
                    try:
                        saved_state = WorkflowStateStore(database_url=database_url).load(plan_id)
                    except Exception:
                        raise ProviderError("Persistent provisioning state could not be verified; refusing to reuse existing cloud resources") from None
                else:
                    state_path = Path.home() / ".business-app-provisioner" / "runs" / f"{plan_id}.json"
                    if not state_path.is_file():
                        saved_state = None
                    else:
                        try:
                            saved_state = json.loads(state_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError):
                            raise ProviderError("Local provisioning state could not be verified; refusing to reuse existing cloud resources") from None
                if saved_state is not None:
                    if not isinstance(saved_state, dict) or saved_state.get("plan_id") != plan_id or saved_state.get("business_slug") != slug:
                        raise ProviderError("Saved provisioning state does not match this business plan")
                    known_resources = saved_state.get("resources") or {}
                    if provisioning_marker is None:
                        provisioning_marker = saved_state.get("provisioning_marker")
                    if pending_operations is None:
                        pending_operations = saved_state.get("resource_operations") or {}
                    if not isinstance(known_resources, dict):
                        raise ProviderError("Provisioning resource ownership state is invalid")
        if not isinstance(known_resources, dict):
            raise ProviderError("Provisioning resource ownership state is invalid")
        pending_operations = pending_operations or {}
        if not isinstance(pending_operations, dict):
            raise ProviderError("Provisioning recovery operation state is invalid")

        def operation_is_pending(step):
            operation = pending_operations.get(step)
            return isinstance(operation, dict) and operation.get("status") in {
                "intent", "unknown", "reconciling"
            }

        if any(operation_is_pending(step) for step in (
            "github_repository", "neon_project", "render_service"
        )):
            if not isinstance(provisioning_marker, str) or not re.fullmatch(r"[a-f0-9]{32}", provisioning_marker):
                raise ProviderError(
                    "A previous cloud create has no valid recovery marker; manual reconciliation is required"
                )
        if not github_owner or not isinstance(github_owner, str):
            raise ProviderError("GITHUB_OWNER is required")
        if not getattr(self.render, "workspace_id", None):
            raise ProviderError("RENDER_WORKSPACE_ID must identify the approved workspace")
        if not getattr(self.neon, "org_id", None):
            raise ProviderError("NEON_ORG_ID must identify the approved Neon organization")

        connections = {
            "github": self.github.check_connection(),
            "neon": self.neon.check_connection(),
            "render": self.render.check_connection(),
        }
        # A successful HTTP response is not enough: every provider must explicitly
        # confirm authenticated access. Render must also confirm the exact selected
        # workspace, not merely that some workspace is visible.
        for provider_name, result in connections.items():
            if not isinstance(result, dict) or result.get("connected") is not True:
                raise ProviderError(f"{provider_name.title()} connection could not be verified")
        if connections["render"].get("workspace_selected") is not True:
            raise ProviderError("Render did not verify access to the selected workspace")
        if plan.get("ownership_mode", "managed") == "customer_owned":
            self._check_customer_owned_provider_identity(plan, github_owner=github_owner, connections=connections)

        repository = self.github.get_repository(github_owner, slug)
        if repository and repository.get("private") is not True:
            raise ProviderError("A repository with this name already exists but is not private")
        if repository:
            recorded_repository = known_resources.get("github") or {}
            id_matches = (
                repository.get("id")
                and str(recorded_repository.get("repository_id")) == str(repository.get("id"))
            )
            marker_matches = bool(
                provisioning_marker
                and self.github.repository_has_provisioning_marker(repository, provisioning_marker)
            )
            if not (id_matches or marker_matches):
                if operation_is_pending("github_repository"):
                    raise ProviderOperationUnknown(
                        "GitHub repository is visible but its ownership marker cannot yet be verified"
                    )
                raise ProviderError("A GitHub repository with this name already exists but is not registered to this provisioning workflow")
        elif operation_is_pending("github_repository"):
            raise ProviderOperationUnknown(
                "GitHub repository create outcome is still unknown; no second create request will be sent"
            )
        repository_url = (
            (repository or {}).get("html_url")
            or f"https://github.com/{github_owner}/{slug}"
        )

        region = (plan.get("infrastructure") or {}).get("region", "frankfurt")
        if region != "frankfurt":
            raise ProviderError("The requested deployment region is not supported by this provisioning workflow")
        neon_region = "aws-eu-central-1"
        projects = [
            item for item in self.neon.list_projects()
            if (item.get("name") or "").casefold() == slug.casefold()
        ]
        if len(projects) > 1:
            raise ProviderError("Multiple Neon projects have this name; choose the intended project explicitly")
        project = projects[0] if projects else None
        if project and project.get("region_id") != neon_region:
            raise ProviderError("A Neon project with this name exists in a different region")
        neon_org_id = getattr(self.neon, "org_id", None)
        if project and project.get("org_id") and project.get("org_id") != neon_org_id:
            raise ProviderError("A Neon project with this name belongs to a different organization")
        if project:
            recorded_project = known_resources.get("neon") or {}
            id_matches = (
                project.get("id")
                and str(recorded_project.get("project_id")) == str(project.get("id"))
            )
            marker_matches = False
            if not id_matches and provisioning_marker:
                try:
                    marker_matches = bool(
                        project.get("id")
                        and self.neon.project_has_provisioning_marker(
                            project.get("id"), provisioning_marker
                        )
                    )
                except ProviderError:
                    if operation_is_pending("neon_project"):
                        raise ProviderOperationUnknown(
                            "Neon project is visible but its recovery branch cannot yet be verified"
                        ) from None
                    raise
            if not (id_matches or marker_matches):
                if operation_is_pending("neon_project"):
                    raise ProviderOperationUnknown(
                        "Neon project is visible but its default-branch ownership marker is not yet verifiable"
                    )
                raise ProviderError("A Neon project with this name already exists but is not registered to this provisioning workflow")
        elif operation_is_pending("neon_project"):
            raise ProviderOperationUnknown(
                "Neon project create outcome is still unknown; no second create request will be sent"
            )

        services = [
            item for item in self.render.list_services()
            if (item.get("name") or "").casefold() == slug.casefold()
        ]
        if len(services) > 1:
            raise ProviderError("Multiple Render services have this name; choose the intended service explicitly")
        service = services[0] if services else None
        if service:
            recorded_service = known_resources.get("render") or {}
            id_matches = (
                service.get("id")
                and str(recorded_service.get("service_id")) == str(service.get("id"))
            )
            marker_matches = False
            if not id_matches and provisioning_marker:
                try:
                    marker_matches = bool(
                        service.get("id")
                        and self.render.service_has_provisioning_marker(
                            service.get("id"), provisioning_marker
                        )
                    )
                except ProviderError:
                    if operation_is_pending("render_service"):
                        raise ProviderOperationUnknown(
                            "Render service is visible but its environment ownership marker cannot yet be verified"
                        ) from None
                    raise
            if not (id_matches or marker_matches):
                if operation_is_pending("render_service"):
                    raise ProviderOperationUnknown(
                        "Render service is visible but its environment ownership marker is not yet verifiable"
                    )
                raise ProviderError("A Render service with this name already exists but is not registered to this provisioning workflow")
            details = service.get("serviceDetails") or {}
            if self._normalize_repository_url(service.get("repo")) != self._normalize_repository_url(repository_url):
                raise ProviderError("A Render service with this name exists but has a different source repository")
            if service.get("type") != "web_service" or service.get("branch") != "main":
                raise ProviderError("A Render service with this name exists but has a different type or branch")
            if details.get("plan") != "free" or details.get("region") != "frankfurt":
                raise ProviderError("Existing Render service is not configured for the requested Free Frankfurt target")
            if service.get("autoDeployTrigger") != "checksPass":
                raise ProviderError("Existing Render service does not use CI-gated auto-deploy")
        elif operation_is_pending("render_service"):
            raise ProviderOperationUnknown(
                "Render service create outcome is still unknown; no second create request will be sent"
            )

        return {
            "mode": "read_only_preflight",
            "plan_id": plan.get("plan_id"),
            "business_slug": slug,
            "read_only": True,
            "writes_performed": False,
            "provider_connections": {
                name: {
                    "connected": bool(result.get("connected")),
                    "account": result.get("account"),
                    "workspace_selected": result.get("workspace_selected"),
                }
                for name, result in connections.items()
            },
            "resources": {
                "github": {
                    "status": "existing_private" if repository else "would_create_private",
                    "repository": repository.get("full_name") if repository else f"{github_owner}/{slug}",
                },
                "neon": {
                    "status": "existing" if project else "would_create",
                    "region": neon_region,
                },
                "render": {
                    "status": "existing" if service else "would_create",
                    "plan": "free",
                    "region": "frankfurt",
                    "workspace_selected": True,
                },
            },
            "cost_policy": {
                "paid_resources_allowed": False,
                "neon_free_tier_verified": False,
                "manual_zero_cost_verification_required_before_execution": True,
            },
            "next_step": "Review this report and verify current Neon free-tier eligibility and provider pricing before any separately approved CREATE operation.",
        }

    def run(self, plan, *, github_owner, admin_password, approval,
            neon_free_tier_verified=False, workflow_url=None):
        """Serialize Execute for one plan across local processes and remote workers."""
        if not isinstance(plan, dict):
            raise ProviderError("Only a valid dry-run provisioning plan can be executed")
        business = plan.get("business") or {}
        # Serialize by the durable business identity, not the ephemeral plan id.
        # A user can generate multiple plans for the same business slug; those
        # plans must not race to create the same provider resources.
        workflow_id = business.get("slug") or plan.get("plan_id")
        if not isinstance(workflow_id, str) or not workflow_id:
            raise ProviderError("Provisioning plan is missing a workflow identifier")
        if self.state_store is None:
            self.state_store = WorkflowStateStore()
        with self.state_store.claim(workflow_id):
            return self._run_claimed(
                plan,
                github_owner=github_owner,
                admin_password=admin_password,
                approval=approval,
                neon_free_tier_verified=neon_free_tier_verified,
                workflow_url=workflow_url,
            )

    def _run_claimed(self, plan, *, github_owner, admin_password, approval,
            neon_free_tier_verified=False, workflow_url=None):
        if approval != "CREATE":
            raise ProviderError("Provisioning requires the explicit confirmation text CREATE")
        if neon_free_tier_verified is not True:
            raise ProviderError("Neon project creation is blocked until zero-cost/free-tier eligibility is explicitly verified")
        if not isinstance(admin_password, str) or len(admin_password) < 14:
            raise ProviderError("A customer admin password of at least 14 characters is required")
        if not isinstance(plan, dict) or plan.get("mode") != "dry_run":
            raise ProviderError("Only a valid dry-run provisioning plan can be executed")
        self._require_customer_owned_connections(plan)
        business = plan.get("business") or {}
        slug = business.get("slug")
        if not isinstance(slug, str) or not slug:
            raise ProviderError("Provisioning plan is missing a business slug")
        selected_modules = set((plan.get("application") or {}).get("modules") or [])
        required_integration_secrets = set()
        if "whatsapp_inbound" in selected_modules:
            required_integration_secrets.update({"WHATSAPP_APP_SECRET", "WHATSAPP_VERIFY_TOKEN"})
        if "automation_webhooks" in selected_modules:
            required_integration_secrets.add("AUTOMATION_WEBHOOK_SECRET")
        missing_integration_secrets = sorted(
            key for key in required_integration_secrets if not os.getenv(key, "").strip()
        )
        if missing_integration_secrets:
            raise ProviderError(
                "Selected integrations require local environment variables before provisioning: "
                + ", ".join(missing_integration_secrets)
            )
        if not github_owner:
            raise ProviderError("GITHUB_OWNER is required")
        if not getattr(self.render, "workspace_id", None):
            raise ProviderError("RENDER_WORKSPACE_ID must identify the approved workspace")
        if not getattr(self.neon, "org_id", None):
            raise ProviderError("NEON_ORG_ID must identify the approved Neon organization")

        # Keep read-only preflight free of local filesystem side effects.
        if self.state_store is None:
            self.state_store = WorkflowStateStore()

        workflow_id = plan.get("plan_id") or slug
        state = self.state_store.load(workflow_id)
        if state is not None and (
            not isinstance(state, dict)
            or state.get("plan_id") != plan.get("plan_id")
            or state.get("business_slug") != slug
        ):
            raise ProviderError("Saved provisioning state does not match this business plan")
        state = state or {
            "plan_id": plan.get("plan_id"),
            "business_slug": slug,
            "business_name": str(business.get("name") or slug)[:200],
            "modules": list((plan.get("application") or {}).get("modules") or []),
            "status": "not_started",
            "step": "not_started",
            "resources": {},
            "resource_operations": {},
            "provisioning_marker": secrets.token_hex(16),
            "history": [],
            "error": None,
        }
        if not isinstance(state.get("resource_operations", {}), dict):
            raise ProviderError("Saved provisioning recovery operation state is invalid")
        state.setdefault("resource_operations", {})
        if not state.get("provisioning_marker"):
            if any(
                isinstance(operation, dict)
                and operation.get("status") in {"intent", "unknown", "reconciling"}
                for operation in state["resource_operations"].values()
            ):
                raise ProviderError(
                    "Saved provisioning state has an unresolved create without a recovery marker; manual reconciliation is required"
                )
            state["provisioning_marker"] = secrets.token_hex(16)
        if not re.fullmatch(r"[a-f0-9]{32}", str(state.get("provisioning_marker", ""))):
            raise ProviderError("Saved provisioning recovery marker is invalid")

        def record(step, status, details=None, error=None):
            state["step"] = step
            state["status"] = status
            state["error"] = error
            entry = {"step": step, "status": status, "at": _utc_now()}
            if details:
                entry["details"] = details
            state.setdefault("history", []).append(entry)
            self.state_store.save(workflow_id, state)

        def begin_resource_operation(step, provider, resource_name):
            operations = state.setdefault("resource_operations", {})
            previous = operations.get(step)
            previous_status = previous.get("status") if isinstance(previous, dict) else None
            allow_create = previous is None or previous_status == "failed"
            operations[step] = {
                "provider": provider,
                "resource_name": str(resource_name)[:200],
                "marker": state["provisioning_marker"],
                "status": "intent" if allow_create else "reconciling",
                "updated_at": _utc_now(),
            }
            record(step, "running", {
                "resource_name": str(resource_name)[:200],
                "recovery_mode": "create" if allow_create else "reconcile_only",
            })
            return allow_create

        def complete_resource_operation(step, resource_id):
            operation = state.setdefault("resource_operations", {}).setdefault(step, {})
            operation["status"] = "completed"
            operation["resource_id"] = str(resource_id)[:200] if resource_id is not None else None
            operation["updated_at"] = _utc_now()

        try:
            record("preflight", "running")
            preflight_report = self.preflight(
                plan,
                github_owner=github_owner,
                known_resources=state.get("resources", {}),
                provisioning_marker=state["provisioning_marker"],
                pending_operations=state.get("resource_operations", {}),
            )
            record("preflight", "completed", {
                "read_only": preflight_report["read_only"],
                "writes_performed": preflight_report["writes_performed"],
                "resources": preflight_report["resources"],
            })

            record("starter_export", "running")
            with tempfile.TemporaryDirectory(prefix="business-app-export-") as temporary:
                export_path = Path(temporary) / slug
                export_starter(
                    export_path,
                    business_name=business.get("name", slug),
                    slug=slug,
                    modules=(plan.get("application") or {}).get("modules", []),
                    business_profile=business,
                )

                allow_create = begin_resource_operation(
                    "github_repository", "github", f"{github_owner}/{slug}"
                )
                repo_result = self.github.ensure_private_repository(
                    github_owner, slug,
                    expected_repository_id=(state.get("resources", {}).get("github") or {}).get("repository_id"),
                    provisioning_marker=state["provisioning_marker"],
                    allow_create=allow_create,
                )
                repository = repo_result["repository"]
                if repository.get("private") is not True:
                    raise ProviderError("GitHub did not confirm a private repository")
                state["resources"]["github"] = {
                    "repository_id": repository.get("id"),
                    "repository": repository.get("full_name") or f"{github_owner}/{slug}",
                    "url": repository.get("html_url"),
                    "created": repo_result.get("created", False),
                }
                complete_resource_operation("github_repository", repository.get("id"))
                record("github_repository", "completed", state["resources"]["github"])

                branch_name = f"provisioning/{plan.get('plan_id')}"
                record("github_branch", "running", {"branch": branch_name})
                branch_result = self.github.ensure_branch(
                    github_owner, slug, branch_name, base_branch="main"
                )
                record("github_branch", "completed", {
                    "branch": branch_name,
                    "created": branch_result.get("created", False),
                })

                record("github_publish", "running")
                publish_result = self.github.publish_directory(
                    github_owner, slug, export_path, branch=branch_name,
                    commit_message=f"Provision {business.get('name', slug)} starter",
                )
                state["resources"]["github"]["published_commit"] = publish_result.get("commit_sha")
                state["resources"]["github"]["file_count"] = publish_result.get("file_count")
                record("github_publish", "completed", {
                    "commit": publish_result.get("commit_sha"),
                    "file_count": publish_result.get("file_count"),
                    "changed": publish_result.get("published"),
                    "branch": branch_name,
                })

                record("github_pull_request", "running", {"branch": branch_name})
                pr_result = self.github.create_or_get_pull_request(
                    github_owner, slug, branch_name, base="main",
                    title=f"Provision {business.get('name', slug)} starter",
                    body=(
                        "Automated provisioning change. The starter is published to an isolated branch. "
                        "The provisioning workflow will continue only after all GitHub Actions checks pass."
                    ),
                )
                pull_request = pr_result["pull_request"]
                pr_number = pull_request.get("number")
                if not pr_number:
                    raise ProviderError("GitHub did not return the provisioning pull request number")
                state["resources"]["github"]["pull_request"] = {
                    "number": pr_number,
                    "url": pull_request.get("html_url"),
                    "branch": branch_name,
                }
                record("github_pull_request", "completed", {
                    "number": pr_number,
                    "url": pull_request.get("html_url"),
                    "merged": pr_result.get("merged", False),
                })

                if not pr_result.get("merged", False):
                    record("github_ci", "running", {"pull_request": pr_number})
                    checks = self.github.get_pull_request_checks(github_owner, slug, pr_number)
                    if not checks.get("ready"):
                        reason = checks.get("reason", "checks_pending")
                        record("github_ci", "waiting", {
                            "pull_request": pr_number,
                            "reason": reason,
                            "checks": checks.get("checks", []),
                        })
                        raise ProviderError(
                            f"GitHub PR #{pr_number} is awaiting successful CI checks ({reason}). "
                            "Run Preflight and Execute again after GitHub Actions completes."
                        )
                    record("github_ci", "completed", {
                        "pull_request": pr_number,
                        "head_sha": checks.get("head_sha"),
                        "checks": checks.get("checks", []),
                    })
                    record("github_merge", "running", {"pull_request": pr_number})
                    merge_result = self.github.merge_pull_request(
                        github_owner, slug, pr_number,
                        expected_head_sha=checks["head_sha"],
                    )
                    state["resources"]["github"]["merge_commit"] = merge_result.get("sha")
                    record("github_merge", "completed", {
                        "pull_request": pr_number,
                        "merge_commit": merge_result.get("sha"),
                    })
                else:
                    state["resources"]["github"]["merge_commit"] = pull_request.get("merge_commit_sha")
                    record("github_merge", "completed", {
                        "pull_request": pr_number,
                        "already_merged": True,
                        "merge_commit": pull_request.get("merge_commit_sha"),
                    })

            allow_create = begin_resource_operation("neon_project", "neon", slug)
            project_result = self.neon.ensure_project(
                slug,
                free_tier_verified=True,
                expected_project_id=(state.get("resources", {}).get("neon") or {}).get("project_id"),
                provisioning_marker=state["provisioning_marker"],
                allow_create=allow_create,
            )
            project = project_result["project"]
            project_id = project.get("id")
            if not project_id:
                raise ProviderError("Neon did not return a project identifier")
            state["resources"]["neon"] = {
                "project_id": project_id,
                "org_id": getattr(self.neon, "org_id", None),
                "project_name": project.get("name", slug),
                "region": project.get("region_id"),
                "created": project_result.get("created", False),
            }
            complete_resource_operation("neon_project", project_id)
            record("neon_project", "completed", state["resources"]["neon"])

            record("neon_connection", "running")
            database_uri = self.neon.get_connection_uri(project_id)
            if not isinstance(database_uri, str) or not database_uri.startswith(("postgres://", "postgresql://")):
                raise ProviderError("Neon returned an invalid PostgreSQL connection URI")
            record("neon_connection", "completed", {"database_connection": "received; not persisted"})

            previous_render_operation = (state.get("resource_operations") or {}).get("render_service")
            preserve_existing_render_secrets = (
                isinstance(previous_render_operation, dict)
                and previous_render_operation.get("status") in {
                    "intent", "unknown", "reconciling", "completed"
                }
            )
            render_env = {
                "BUSINESS_STUDIO_PROVISIONING_ID": state["provisioning_marker"],
                "DATABASE_URL": database_uri,
                "PYTHON_VERSION": "3.11.9",
                "FLASK_ENV": "production",
                "TRUST_PROXY_HEADERS": "true",
            }
            if not preserve_existing_render_secrets:
                render_env["SECRET_KEY"] = secrets.token_urlsafe(48)
                render_env["ADMIN_PASSWORD_HASH"] = generate_password_hash(admin_password)
                for secret_name in (
                    "WHATSAPP_APP_SECRET", "WHATSAPP_VERIFY_TOKEN",
                    "AUTOMATION_WEBHOOK_SECRET",
                ):
                    secret_value = os.getenv(secret_name, "").strip()
                    if secret_value:
                        render_env[secret_name] = secret_value
            # A retry must not silently rotate an already-created app's Flask
            # session key, admin password hash, or integration credentials.
            # Those values were sent in the original Render create request and
            # remain managed by Render; intentional rotation is a separate action.
            repository_url = repository.get("html_url") or f"https://github.com/{github_owner}/{slug}"
            allow_create = begin_resource_operation("render_service", "render", slug)
            service_result = self.render.ensure_web_service(
                name=slug,
                repository_url=repository_url,
                branch="main",
                env_vars=render_env,
                expected_service_id=(state.get("resources", {}).get("render") or {}).get("service_id"),
                provisioning_marker=state["provisioning_marker"],
                allow_create=allow_create,
            )
            service = service_result["service"]
            service_id = service.get("id")
            if not service_id:
                raise ProviderError("Render did not return a service identifier")
            state["resources"]["render"] = {
                "service_id": service_id,
                "workspace_id": getattr(self.render, "workspace_id", None),
                "service_name": service.get("name", slug),
                "url": (service.get("serviceDetails") or {}).get("url") or service.get("url"),
                "created": service_result.get("created", False),
                "plan": "free",
                "region": "frankfurt",
            }
            complete_resource_operation("render_service", service_id)
            record("render_service", "completed", state["resources"]["render"])

            # A retry may discover a service created by an earlier run whose
            # response/state write was interrupted. Refresh its required runtime
            # configuration before checking health; otherwise old credentials
            # (or a different Neon project) could remain active indefinitely.
            if not service_result.get("created", False):
                record("render_environment", "running")
                deploy = self.render.reconcile_environment_and_deploy(service_id, render_env)
                record("render_environment", "completed", {
                    "deploy_id": deploy.get("id"),
                    "message": "Required environment variables reconciled; deploy requested",
                })

            record("health_check", "running")
            health_service = service
            details = service.get("serviceDetails") or {}
            if not (details.get("url") or service.get("url")) and hasattr(self.render, "get_service"):
                health_service = self.render.get_service(service_id)
            health_url = self._wait_for_health(health_service, workflow_url=workflow_url)
            state["resources"]["render"]["health_url"] = health_url
            record("health_check", "completed", {"health_url": health_url})
            record("completed", "completed", {"message": "Provisioning completed; no secrets were persisted"})
            return {
                "workflow_id": workflow_id,
                "status": "completed",
                "resources": state["resources"],
            }
        except Exception as exc:
            # Provider adapters intentionally expose sanitized errors. Never serialize input secrets.
            safe_error = str(exc)
            for secret in (admin_password,):
                if secret:
                    safe_error = safe_error.replace(secret, "[REDACTED]")
            operation = state.get("resource_operations", {}).get(state.get("step"))
            if isinstance(operation, dict) and operation.get("status") in {"intent", "reconciling"}:
                outcome_unknown = (
                    isinstance(exc, ProviderOperationUnknown)
                    or (isinstance(exc, ProviderHTTPError) and exc.status >= 500)
                )
                operation["status"] = "unknown" if outcome_unknown else "failed"
                operation["last_error_code"] = (
                    "provider_outcome_unknown" if outcome_unknown else "operation_failed"
                )
                operation["updated_at"] = _utc_now()
            state["resources"] = state.get("resources", {})
            record(state.get("step", "unknown"), "failed", error=safe_error[:500])
            raise ProviderError(f"Provisioning stopped at {state.get('step')}: {safe_error}") from None
