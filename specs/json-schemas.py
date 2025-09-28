#!/usr/bin/env python3
"""
Generate JSON Schema files from Pydantic models
Run this to create machine-readable schema files for external tools
"""

import json
from pathlib import Path
from typing import Dict, Any

from schemas import (
    Authorization, AssessmentPlan, ToolRunRequest, ToolRunResult,
    NDJSONEvent, RunManifest, APIResponse, RunStatusResponse
)


def generate_json_schemas() -> Dict[str, Dict[str, Any]]:
    """Generate JSON Schema definitions for all key models"""

    schemas = {
        "authorization": Authorization.model_json_schema(),
        "assessment_plan": AssessmentPlan.model_json_schema(),
        "tool_run_request": ToolRunRequest.model_json_schema(),
        "tool_run_result": ToolRunResult.model_json_schema(),
        "ndjson_event": {
            "oneOf": [
                {"$ref": "#/definitions/PlanEvent"},
                {"$ref": "#/definitions/PhaseStartEvent"},
                {"$ref": "#/definitions/PhaseEndEvent"},
                {"$ref": "#/definitions/ToolStartEvent"},
                {"$ref": "#/definitions/ToolOutputEvent"},
                {"$ref": "#/definitions/ToolEndEvent"},
                {"$ref": "#/definitions/ApprovalRequiredEvent"},
                {"$ref": "#/definitions/ApprovalResultEvent"},
                {"$ref": "#/definitions/ErrorEvent"},
                {"$ref": "#/definitions/FinalReportEvent"},
            ]
        },
        "run_manifest": RunManifest.model_json_schema(),
        "api_response": APIResponse.model_json_schema(),
        "run_status_response": RunStatusResponse.model_json_schema(),
    }

    return schemas


def save_schemas_to_files():
    """Save individual schema files for easy reference"""
    schema_dir = Path("specs/json-schemas")
    schema_dir.mkdir(exist_ok=True)

    schemas = generate_json_schemas()

    for name, schema in schemas.items():
        schema_file = schema_dir / f"{name}.json"
        with open(schema_file, 'w') as f:
            json.dump(schema, f, indent=2)
        print(f"Generated {schema_file}")

    # Create combined schema file
    combined_file = schema_dir / "all_schemas.json"
    with open(combined_file, 'w') as f:
        json.dump(schemas, f, indent=2)
    print(f"Generated {combined_file}")


if __name__ == "__main__":
    save_schemas_to_files()