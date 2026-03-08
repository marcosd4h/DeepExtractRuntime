"""Parser for NtApiDotNet-generated C# RPC client stubs.

Extracts per-procedure parameter type signatures from auto-generated ``.cs``
client stub files (one per RPC interface).  These stubs contain the actual
NDR-marshaled parameter types that the runtime's analysis data does not
otherwise provide.

The type system handled here mirrors NtApiDotNet's ``NtCoreLib/Ndr/Marshal/``
hierarchy: NdrContextHandle, NdrInt3264, NdrUInt3264, NdrEnum16, NdrEmpty,
NdrPipe<T>, NdrEmbeddedPointer<T>, NdrInterfacePointer, NdrUnsupported,
NdrSystemHandle, System.Nullable<T>, plus standard C# primitives and
generated Struct_N / Union_N complex types.

Typical usage::

    from helpers.rpc_stub_parser import load_stubs_from_directory, parse_stub_file

    stubs = load_stubs_from_directory("config/assets/rpc_data/rpc_clients_26200_7840")
    sig = stubs["f6beaff7-1e19-4fbb-9f8f-b89e2018337c"][0]
    print(sig.name, sig.parameters)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type risk scoring
# ---------------------------------------------------------------------------

_TYPE_RISK: dict[str, float] = {
    "string": 0.8,
    "byte[]": 0.9,
    "sbyte[]": 0.9,
    "int": 0.3,
    "uint": 0.3,
    "long": 0.3,
    "ulong": 0.3,
    "short": 0.3,
    "ushort": 0.3,
    "char": 0.3,
    "double": 0.3,
    "float": 0.3,
    "bool": 0.1,
    "System.Guid": 0.2,
    "NdrContextHandle": 0.2,
    "NdrEnum16": 0.2,
    "NdrInt3264": 0.4,
    "NdrUInt3264": 0.4,
    "NdrEmpty": 0.0,
    "NdrUnsupported": 0.1,
    "NdrInterfacePointer": 0.7,
    "NdrSystemHandle": 0.7,
    "IntPtr": 0.5,
}

# Wrapper types whose inner type determines the actual semantics.
_WRAPPER_PREFIXES = (
    "NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer",
    "NtApiDotNet.Ndr.Marshal.NdrPipe",
    "System.Nullable",
)

# Fully qualified prefixes to strip during type simplification.
_NS_PREFIXES = (
    "NtApiDotNet.Ndr.Marshal.",
    "NtApiDotNet.Win32.Rpc.Client.",
    "NtApiDotNet.Win32.Rpc.",
    "NtApiDotNet.",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RpcParameter:
    """A single parameter in an RPC procedure signature."""

    name: str
    ndr_type: str
    direction: str  # "in", "out", "inout"
    is_array: bool = False
    is_pointer: bool = False
    is_pipe: bool = False
    is_nullable: bool = False

    @property
    def risk_score(self) -> float:
        """Heuristic risk score based on the NDR type (0.0--1.0 scale)."""
        base = self.ndr_type.rstrip("[]")
        if self.is_array and base in ("byte", "sbyte"):
            return 0.9
        if self.is_array and base == "string":
            return 0.85
        if self.is_pipe:
            return 0.75
        if self.ndr_type == "NdrInterfacePointer" or self.ndr_type == "NdrSystemHandle":
            return 0.7
        if self.is_array:
            return max(_TYPE_RISK.get(base, 0.5), 0.6)
        if base.startswith("Struct_") or base.startswith("Union_"):
            return 0.6
        return _TYPE_RISK.get(base, 0.5)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "ndr_type": self.ndr_type,
            "direction": self.direction,
            "is_array": self.is_array,
            "is_pointer": self.is_pointer,
            "risk_score": round(self.risk_score, 2),
        }
        if self.is_pipe:
            d["is_pipe"] = True
        if self.is_nullable:
            d["is_nullable"] = True
        return d


@dataclass
class RpcProcedureSignature:
    """Typed signature for a single RPC procedure."""

    name: str
    opnum: int
    parameters: list[RpcParameter] = field(default_factory=list)
    return_type: str = "uint"

    @property
    def input_parameter_count(self) -> int:
        return sum(1 for p in self.parameters if p.direction in ("in", "inout"))

    @property
    def output_parameter_count(self) -> int:
        return sum(1 for p in self.parameters if p.direction in ("out", "inout"))

    @property
    def max_input_risk(self) -> float:
        """Highest risk score among input parameters."""
        scores = [p.risk_score for p in self.parameters if p.direction in ("in", "inout")]
        return max(scores) if scores else 0.0

    @property
    def has_string_inputs(self) -> bool:
        return any(
            "string" in p.ndr_type.lower() and p.direction in ("in", "inout")
            for p in self.parameters
        )

    @property
    def has_byte_buffer_inputs(self) -> bool:
        return any(
            p.is_array and p.ndr_type.rstrip("[]") in ("byte", "sbyte")
            and p.direction in ("in", "inout")
            for p in self.parameters
        )

    @property
    def has_pipe_parameters(self) -> bool:
        return any(p.is_pipe for p in self.parameters)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "opnum": self.opnum,
            "return_type": self.return_type,
            "parameters": [p.to_dict() for p in self.parameters],
            "input_count": self.input_parameter_count,
            "output_count": self.output_parameter_count,
            "max_input_risk": round(self.max_input_risk, 2),
            "has_string_inputs": self.has_string_inputs,
            "has_byte_buffer_inputs": self.has_byte_buffer_inputs,
        }


@dataclass
class RpcStubFile:
    """Parsed content of a single C# client stub file."""

    interface_id: str
    interface_version: str
    source_executable: str
    procedures: list[RpcProcedureSignature] = field(default_factory=list)
    complex_type_count: int = 0

    @property
    def procedure_count(self) -> int:
        return len(self.procedures)

    def get_procedure(self, name: str) -> Optional[RpcProcedureSignature]:
        for proc in self.procedures:
            if proc.name == name:
                return proc
        return None

    def get_high_risk_procedures(self, threshold: float = 0.7) -> list[RpcProcedureSignature]:
        return [p for p in self.procedures if p.max_input_risk >= threshold]

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface_id": self.interface_id,
            "interface_version": self.interface_version,
            "source_executable": self.source_executable,
            "procedure_count": self.procedure_count,
            "complex_type_count": self.complex_type_count,
            "procedures": [p.to_dict() for p in self.procedures],
        }


# ---------------------------------------------------------------------------
# Type simplification
# ---------------------------------------------------------------------------

def _simplify_type(raw: str) -> tuple[str, bool, bool]:
    """Simplify a fully-qualified C# type to a short form.

    Returns ``(simplified_name, is_pointer, is_pipe)``.
    Unwraps NdrEmbeddedPointer<T>, NdrPipe<T>, and System.Nullable<T>.
    """
    t = raw.strip()
    is_pointer = False
    is_pipe = False

    for prefix in _WRAPPER_PREFIXES:
        if t.startswith(prefix):
            bracket_start = t.find("<", len(prefix))
            if bracket_start >= 0 and t.endswith(">"):
                inner = t[bracket_start + 1 : -1]
                if "NdrEmbeddedPointer" in prefix:
                    is_pointer = True
                elif "NdrPipe" in prefix:
                    is_pipe = True
                inner_simplified, inner_ptr, inner_pipe = _simplify_type(inner)
                return inner_simplified, is_pointer or inner_ptr, is_pipe or inner_pipe

    for ns in _NS_PREFIXES:
        if t.startswith(ns):
            t = t[len(ns):]
            break

    if "IntPtr" in raw and not is_pointer:
        is_pointer = True

    return t, is_pointer, is_pipe


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_HEADER_IFACE_RE = re.compile(r"//\s*Interface ID:\s*(.+)")
_HEADER_VERSION_RE = re.compile(r"//\s*Interface Version:\s*(.+)")
_HEADER_SOURCE_RE = re.compile(r"//\s*Source Executable:\s*(.+)")

_STRUCT_RE = re.compile(r"struct\s+(Struct_\d+|Union_\d+)")

_CLIENT_METHOD_RE = re.compile(
    r"public\s+(uint|int|void)\s+(\w+)\s*\(([^)]*)\)",
)

_SKIP_METHODS = frozenset({"Client", "Dispose", "Connect", "Disconnect"})


def _parse_parameter(raw: str) -> Optional[RpcParameter]:
    """Parse a single C# parameter declaration."""
    raw = raw.strip()
    if not raw:
        return None

    direction = "in"
    if raw.startswith("out "):
        direction = "out"
        raw = raw[4:].strip()
    elif raw.startswith("ref "):
        direction = "inout"
        raw = raw[4:].strip()

    parts = raw.rsplit(None, 1)
    if len(parts) < 2:
        return None

    raw_type = parts[0]
    param_name = parts[1]

    type_str, is_pointer, is_pipe = _simplify_type(raw_type)
    is_array = type_str.endswith("[]")
    is_nullable = raw_type.lstrip().startswith("System.Nullable")

    return RpcParameter(
        name=param_name,
        ndr_type=type_str,
        direction=direction,
        is_array=is_array,
        is_pointer=is_pointer,
        is_pipe=is_pipe,
        is_nullable=is_nullable,
    )


def _extract_client_region(text: str) -> str:
    """Extract the Client class body from the full file text.

    Handles multiline method signatures by joining the class body into
    a single logical stream with whitespace normalized.
    """
    lines = text.split("\n")
    in_client = False
    brace_depth = 0
    client_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not in_client:
            if "class Client" in stripped and "RpcClientBase" in stripped:
                in_client = True
                brace_depth = 0
            continue

        for ch in stripped:
            if ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1

        if brace_depth < 0:
            break

        client_lines.append(stripped)

    return " ".join(client_lines)


def parse_stub_file(path: Path) -> Optional[RpcStubFile]:
    """Parse a single C# client stub file.

    Returns ``None`` if the file cannot be parsed or lacks required headers.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _log.warning("Cannot read stub file %s: %s", path, exc)
        return None

    interface_id = ""
    interface_version = ""
    source_executable = ""

    for line in text.split("\n")[:30]:
        m = _HEADER_IFACE_RE.match(line)
        if m:
            interface_id = m.group(1).strip()
        m = _HEADER_VERSION_RE.match(line)
        if m:
            interface_version = m.group(1).strip()
        m = _HEADER_SOURCE_RE.match(line)
        if m:
            source_executable = m.group(1).strip()

    if not interface_id:
        return None

    complex_type_count = len(_STRUCT_RE.findall(text))

    client_body = _extract_client_region(text)

    procedures: list[RpcProcedureSignature] = []
    opnum = 0

    for m in _CLIENT_METHOD_RE.finditer(client_body):
        ret_type = m.group(1)
        method_name = m.group(2)
        params_str = m.group(3).strip()

        if method_name in _SKIP_METHODS:
            continue

        params: list[RpcParameter] = []
        if params_str:
            raw_params = _split_params(params_str)
            for rp in raw_params:
                p = _parse_parameter(rp)
                if p:
                    params.append(p)

        procedures.append(RpcProcedureSignature(
            name=method_name,
            opnum=opnum,
            parameters=params,
            return_type=ret_type,
        ))
        opnum += 1

    return RpcStubFile(
        interface_id=interface_id,
        interface_version=interface_version,
        source_executable=source_executable,
        procedures=procedures,
        complex_type_count=complex_type_count,
    )


def _split_params(params_str: str) -> list[str]:
    """Split a C# parameter list respecting angle brackets for generics."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in params_str:
        if ch == "<":
            depth += 1
            current.append(ch)
        elif ch == ">":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    remainder = "".join(current).strip()
    if remainder:
        parts.append(remainder)
    return parts


# ---------------------------------------------------------------------------
# Directory loader
# ---------------------------------------------------------------------------

def load_stubs_from_directory(
    directory: str | Path,
) -> dict[str, RpcStubFile]:
    """Load all ``.cs`` stub files from *directory*.

    Returns a dict keyed by ``interface_id`` (lowercase).  If multiple
    files map to the same UUID (different versions), only the last one
    is kept.
    """
    d = Path(directory)
    if not d.is_dir():
        _log.warning("Stub directory not found: %s", d)
        return {}

    stubs: dict[str, RpcStubFile] = {}
    for cs_file in sorted(d.glob("*.cs")):
        stub = parse_stub_file(cs_file)
        if stub:
            stubs[stub.interface_id.lower()] = stub

    _log.info("Loaded %d RPC client stubs from %s", len(stubs), d)
    return stubs
