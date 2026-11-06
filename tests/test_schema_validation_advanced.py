from lightguard.policy import validate_json_schema


def test_schema_rejects_invalid_schema_structure():
    # Not a dictionary
    ok, err = validate_json_schema("invalid_string_schema", {"key": "val"})
    assert ok is False
    assert "schema must be a dictionary" in err.lower()

    ok, err = validate_json_schema(12345, {"key": "val"})
    assert ok is False
    assert "schema must be a dictionary" in err.lower()


def test_schema_enum_constraint():
    schema = {
        "type": "string",
        "enum": ["asc", "desc"],
    }
    # Valid
    ok, err = validate_json_schema(schema, "asc")
    assert ok is True
    assert err is None

    # Invalid
    ok, err = validate_json_schema(schema, "random")
    assert ok is False
    assert "not in allowed enum" in err.lower()


def test_schema_numeric_bounds():
    schema = {
        "type": "integer",
        "minimum": 1,
        "maximum": 100,
    }
    # Valid
    ok, _ = validate_json_schema(schema, 50)
    assert ok is True

    # Less than minimum
    ok, err = validate_json_schema(schema, 0)
    assert ok is False
    assert "minimum" in err.lower()

    # Greater than maximum
    ok, err = validate_json_schema(schema, 101)
    assert ok is False
    assert "maximum" in err.lower()


def test_schema_string_constraints():
    schema = {
        "type": "string",
        "minLength": 3,
        "maxLength": 10,
        "pattern": r"^[a-zA-Z0-9_]+$",
    }
    # Valid
    ok, _ = validate_json_schema(schema, "valid_123")
    assert ok is True

    # Too short
    ok, err = validate_json_schema(schema, "ab")
    assert ok is False
    assert "minlength" in err.lower()

    # Too long
    ok, err = validate_json_schema(schema, "this_is_way_too_long")
    assert ok is False
    assert "maxlength" in err.lower()

    # Pattern mismatch
    ok, err = validate_json_schema(schema, "bad-token!")
    assert ok is False
    assert "pattern" in err.lower()


def test_schema_array_constraints():
    schema = {
        "type": "array",
        "items": {"type": "integer"},
        "minItems": 2,
        "maxItems": 4,
    }
    # Valid
    ok, _ = validate_json_schema(schema, [1, 2, 3])
    assert ok is True

    # Too few items
    ok, err = validate_json_schema(schema, [1])
    assert ok is False
    assert "minitems" in err.lower()

    # Too many items
    ok, err = validate_json_schema(schema, [1, 2, 3, 4, 5])
    assert ok is False
    assert "maxitems" in err.lower()
