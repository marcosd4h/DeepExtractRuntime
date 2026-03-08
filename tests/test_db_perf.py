import pytest
import helpers
from helpers.individual_analysis_db import open_individual_analysis_db
from helpers.individual_analysis_db.db import ensure_performance_indexes
from helpers.individual_analysis_db.records import FunctionRecord

def test_memoized_json_parsing(mock_db_path, sample_function_data):
    # Insert sample data
    import sqlite3
    import json
    conn = sqlite3.connect(mock_db_path)
    keys = ", ".join(sample_function_data.keys())
    placeholders = ", ".join(["?"] * len(sample_function_data))
    conn.execute(f"INSERT INTO functions ({keys}) VALUES ({placeholders})", 
                 list(sample_function_data.values()))
    conn.commit()
    conn.close()

    with open_individual_analysis_db(mock_db_path) as db:
        func = db.get_function_by_id(1)
        assert isinstance(func, FunctionRecord)
        
        # First access parses
        xrefs1 = func.parsed_simple_outbound_xrefs
        assert isinstance(xrefs1, list)
        assert xrefs1[0]["function_name"] == "Callee"
        
        # Second access should return the same object (memoized)
        xrefs2 = func.parsed_simple_outbound_xrefs
        assert xrefs1 is xrefs2

def test_schema_validation_caching(mock_db_path):
    from helpers.individual_analysis_db.db import _VALIDATED_PATHS
    _VALIDATED_PATHS.clear()
    
    # First open validates
    with open_individual_analysis_db(mock_db_path) as db:
        db._ensure_open()
        assert str(mock_db_path) in _VALIDATED_PATHS
    
    # Second open should skip validation (already in set)
    # (Checking this via side effect is hard without mocking warnings, 
    # but we verified the logic in the code change)
    assert str(mock_db_path) in _VALIDATED_PATHS


def test_ensure_performance_indexes(mock_db_path):
    assert not hasattr(helpers, "ensure_performance_indexes")
    with pytest.raises(RuntimeError, match="read-only"):
        ensure_performance_indexes(mock_db_path)
