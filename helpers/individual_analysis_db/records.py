"""Dataclasses for individual analysis database rows."""

from __future__ import annotations

import math
from dataclasses import dataclass
import json
from typing import Any, Generic, Optional, TypeVar
from functools import cached_property


def parse_json_safe(raw: Optional[str]) -> Optional[Any]:
    """Safely parse a JSON string, returning *None* on failure.

    Handles ``None``, empty strings, the literal ``"null"``, and non-string
    inputs (already-parsed objects are returned as-is).
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        return raw
    text = raw.strip()
    if not text or text.lower() == "null":
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


# Backward-compat alias used internally by record properties.
_parse_json = parse_json_safe


@dataclass(frozen=True)
class FileInfoRecord:
    file_path: str
    base_dir: Optional[str]
    file_name: Optional[str]
    file_extension: Optional[str]
    file_size_bytes: Optional[int]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    imports: Optional[str]
    exports: Optional[str]
    entry_point: Optional[str]
    file_version: Optional[str]
    product_version: Optional[str]
    company_name: Optional[str]
    file_description: Optional[str]
    internal_name: Optional[str]
    original_filename: Optional[str]
    legal_copyright: Optional[str]
    product_name: Optional[str]
    time_date_stamp_str: Optional[str]
    file_modified_date_str: Optional[str]
    sections: Optional[str]
    pdb_path: Optional[str]
    rich_header: Optional[str]
    tls_callbacks: Optional[str]
    is_net_assembly: Optional[bool]
    clr_metadata: Optional[str]
    idb_cache_path: Optional[str]
    dll_characteristics: Optional[str]
    security_features: Optional[str]
    exception_info: Optional[str]
    load_config: Optional[str]
    analysis_timestamp: Optional[str]

    @cached_property
    def parsed_imports(self) -> Optional[Any]:
        return _parse_json(self.imports)

    @cached_property
    def parsed_exports(self) -> Optional[Any]:
        return _parse_json(self.exports)

    @cached_property
    def parsed_entry_point(self) -> Optional[Any]:
        return _parse_json(self.entry_point)

    @cached_property
    def parsed_sections(self) -> Optional[Any]:
        return _parse_json(self.sections)

    @cached_property
    def parsed_rich_header(self) -> Optional[Any]:
        return _parse_json(self.rich_header)

    @cached_property
    def parsed_tls_callbacks(self) -> Optional[Any]:
        return _parse_json(self.tls_callbacks)

    @cached_property
    def parsed_clr_metadata(self) -> Optional[Any]:
        return _parse_json(self.clr_metadata)

    @cached_property
    def parsed_dll_characteristics(self) -> Optional[Any]:
        return _parse_json(self.dll_characteristics)

    @cached_property
    def parsed_security_features(self) -> Optional[Any]:
        return _parse_json(self.security_features)

    @cached_property
    def parsed_exception_info(self) -> Optional[Any]:
        return _parse_json(self.exception_info)

    @cached_property
    def parsed_load_config(self) -> Optional[Any]:
        return _parse_json(self.load_config)


@dataclass(frozen=True)
class FunctionRecord:
    function_id: int
    function_signature: Optional[str]
    function_signature_extended: Optional[str]
    mangled_name: Optional[str]
    function_name: Optional[str]
    assembly_code: Optional[str]
    decompiled_code: Optional[str]
    inbound_xrefs: Optional[str]
    outbound_xrefs: Optional[str]
    simple_inbound_xrefs: Optional[str]
    simple_outbound_xrefs: Optional[str]
    vtable_contexts: Optional[str]
    global_var_accesses: Optional[str]
    dangerous_api_calls: Optional[str]
    string_literals: Optional[str]
    stack_frame: Optional[str]
    loop_analysis: Optional[str]
    analysis_errors: Optional[str]
    created_at: Optional[str]

    @cached_property
    def parsed_inbound_xrefs(self) -> Optional[Any]:
        return _parse_json(self.inbound_xrefs)

    @cached_property
    def parsed_outbound_xrefs(self) -> Optional[Any]:
        return _parse_json(self.outbound_xrefs)

    @cached_property
    def parsed_simple_inbound_xrefs(self) -> Optional[Any]:
        return _parse_json(self.simple_inbound_xrefs)

    @cached_property
    def parsed_simple_outbound_xrefs(self) -> Optional[Any]:
        return _parse_json(self.simple_outbound_xrefs)

    @cached_property
    def parsed_vtable_contexts(self) -> Optional[Any]:
        return _parse_json(self.vtable_contexts)

    @cached_property
    def parsed_global_var_accesses(self) -> Optional[Any]:
        return _parse_json(self.global_var_accesses)

    @cached_property
    def parsed_dangerous_api_calls(self) -> Optional[Any]:
        return _parse_json(self.dangerous_api_calls)

    @cached_property
    def parsed_string_literals(self) -> Optional[Any]:
        return _parse_json(self.string_literals)

    @cached_property
    def parsed_stack_frame(self) -> Optional[Any]:
        return _parse_json(self.stack_frame)

    @cached_property
    def parsed_loop_analysis(self) -> Optional[Any]:
        return _parse_json(self.loop_analysis)

    @cached_property
    def parsed_analysis_errors(self) -> Optional[Any]:
        return _parse_json(self.analysis_errors)


T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    """Paginated result set with metadata."""

    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return max(1, math.ceil(self.total / self.page_size))

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1


@dataclass(frozen=True)
class FunctionWithModuleInfo:
    """A function record combined with key module-level metadata."""

    function: FunctionRecord
    module_name: Optional[str]
    file_description: Optional[str]
    file_version: Optional[str]
    company_name: Optional[str]
