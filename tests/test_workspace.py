import pytest
from pathlib import Path
from skills._shared._workspace import get_workspace_root, resolve_db_path

def test_get_workspace_root():
    # We simulate a skill script path for the test
    # explorer_output/.agent/skills/test/scripts/test.py
    # parents[4] should be explorer_output
    
    # This test file is at .agent/tests/test_workspace.py
    # parents[2] is workspace root
    root_path = Path(__file__).resolve().parents[2]
    fake_skill_script = root_path / ".agent" / "skills" / "test" / "scripts" / "test.py"
    
    root = get_workspace_root(fake_skill_script)
    assert root.resolve() == root_path.resolve()
    assert (root / ".agent").exists()

def test_resolve_db_path(tmp_path, monkeypatch):
    workspace_root = tmp_path / "repo"
    workspace_root.mkdir()
    (workspace_root / ".agent").mkdir()
    db_dir = workspace_root / "extracted_dbs"
    db_dir.mkdir()
    
    test_db = db_dir / "test.db"
    test_db.touch()
    
    # Test relative path resolution
    resolved = resolve_db_path("extracted_dbs/test.db", workspace_root)
    assert Path(resolved).resolve() == test_db.resolve()
    
    # Test fallback to extracted_dbs
    resolved = resolve_db_path("test.db", workspace_root)
    assert Path(resolved).resolve() == test_db.resolve()
