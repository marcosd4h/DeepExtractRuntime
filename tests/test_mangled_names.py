"""Tests for helpers.mangled_names -- MSVC C++ mangled name parsing."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parent.parent)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from helpers.mangled_names import parse_class_from_mangled


class TestNonCppInputs:
    def test_none_input(self):
        assert parse_class_from_mangled(None) is None

    def test_empty_string(self):
        assert parse_class_from_mangled("") is None

    def test_plain_function_name(self):
        assert parse_class_from_mangled("DllMain") is None

    def test_sub_prefix(self):
        assert parse_class_from_mangled("sub_140001000") is None

    def test_c_linkage_no_question_mark(self):
        assert parse_class_from_mangled("_RtlInitUnicodeString@8") is None


class TestConstructor:
    def test_simple_ctor(self):
        result = parse_class_from_mangled("??0CFoo@@QEAA@XZ")
        assert result is not None
        assert result["class_name"] == "CFoo"
        assert result["role"] == "constructor"
        assert result["mangled"] == "??0CFoo@@QEAA@XZ"
        assert result["namespaces"] == []
        assert result["full_qualified_name"] == "CFoo"

    def test_namespaced_ctor(self):
        result = parse_class_from_mangled("??0MyClass@Details@wil@@QEAA@XZ")
        assert result is not None
        assert result["class_name"] == "MyClass"
        assert result["role"] == "constructor"
        assert result["namespaces"] == ["wil", "Details"]
        assert result["full_qualified_name"] == "wil::Details::MyClass"

    def test_deep_namespace_ctor(self):
        result = parse_class_from_mangled("??0Widget@UI@Internal@App@@QEAA@XZ")
        assert result is not None
        assert result["class_name"] == "Widget"
        assert result["namespaces"] == ["App", "Internal", "UI"]
        assert result["full_qualified_name"] == "App::Internal::UI::Widget"


class TestDestructor:
    def test_simple_dtor(self):
        result = parse_class_from_mangled("??1CFoo@@UEAA@XZ")
        assert result is not None
        assert result["class_name"] == "CFoo"
        assert result["role"] == "destructor"

    def test_namespaced_dtor(self):
        result = parse_class_from_mangled("??1ThreadFailureCallbackHolder@details@wil@@QEAA@XZ")
        assert result is not None
        assert result["class_name"] == "ThreadFailureCallbackHolder"
        assert result["role"] == "destructor"
        assert result["namespaces"] == ["wil", "details"]


class TestVdelDestructor:
    def test_vdel_dtor(self):
        result = parse_class_from_mangled("??_GCFoo@@UEAAPEAXI@Z")
        assert result is not None
        assert result["class_name"] == "CFoo"
        assert result["role"] == "vdel_destructor"


class TestVftable:
    def test_simple_vftable(self):
        result = parse_class_from_mangled("??_7CServer@@6B@")
        assert result is not None
        assert result["class_name"] == "CServer"
        assert result["role"] == "vftable"

    def test_namespaced_vftable(self):
        result = parse_class_from_mangled("??_7Widget@UI@@6B@")
        assert result is not None
        assert result["class_name"] == "Widget"
        assert result["role"] == "vftable"
        assert result["namespaces"] == ["UI"]
        assert result["full_qualified_name"] == "UI::Widget"


class TestRegularMethod:
    def test_public_method(self):
        result = parse_class_from_mangled("?GetCount@CServer@@QEAAHXZ")
        assert result is not None
        assert result["class_name"] == "CServer"
        assert result["method_name"] == "GetCount"
        assert result["role"] == "method"
        assert result["access"] == "public"

    def test_public_virtual_method(self):
        result = parse_class_from_mangled("?Release@CServer@@UEAAKXZ")
        assert result is not None
        assert result["class_name"] == "CServer"
        assert result["method_name"] == "Release"
        assert result["role"] == "method"
        assert result["access"] == "public_virtual"

    def test_private_method(self):
        result = parse_class_from_mangled("?Init@CServer@@AEAAHXZ")
        assert result is not None
        assert result["class_name"] == "CServer"
        assert result["method_name"] == "Init"
        assert result["role"] == "method"
        assert result["access"] == "private"

    def test_protected_method(self):
        result = parse_class_from_mangled("?OnEvent@CServer@@IEAAHXZ")
        assert result is not None
        assert result["class_name"] == "CServer"
        assert result["method_name"] == "OnEvent"
        assert result["role"] == "method"
        assert result["access"] == "protected"

    def test_namespaced_method(self):
        result = parse_class_from_mangled("?DoWork@Worker@Internal@@QEAAHXZ")
        assert result is not None
        assert result["class_name"] == "Worker"
        assert result["method_name"] == "DoWork"
        assert result["namespaces"] == ["Internal"]
        assert result["full_qualified_name"] == "Internal::Worker"

    def test_const_method(self):
        result = parse_class_from_mangled("?Size@Container@@QEBAHXZ")
        assert result is not None
        assert result["class_name"] == "Container"
        assert result["method_name"] == "Size"
        assert result["access"] == "public"


class TestEdgeCases:
    def test_no_separator(self):
        assert parse_class_from_mangled("?broken") is None

    def test_single_at_sign(self):
        assert parse_class_from_mangled("?Func@") is None

    def test_method_with_only_one_part(self):
        """A method mangling needs at least method + class (2 parts before @@)."""
        result = parse_class_from_mangled("?Standalone@@QEAAHXZ")
        assert result is None

    def test_result_contains_mangled_field(self):
        mangled = "??0CFoo@@QEAA@XZ"
        result = parse_class_from_mangled(mangled)
        assert result is not None
        assert result["mangled"] is mangled
