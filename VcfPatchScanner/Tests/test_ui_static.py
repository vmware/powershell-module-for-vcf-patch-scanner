#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# Static regression guards for vcp-patch-ui.html.
# Parses the JS/HTML source to enforce structural invariants that have caused
# regressions when violated.  No browser or external dependencies required.
#
# Run standalone:  python -m unittest discover -s . -p "test_ui_static.py"

import os
import re
import textwrap
import unittest

_UI_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "Tools", "vcp-patch-ui.html",
)


def _load() -> str:
    with open(_UI_PATH, encoding="utf-8") as f:
        return f.read()


def _extract_function(src: str, name: str) -> str:
    """Return the body text of the first JS function with the given name."""
    pattern = rf"function\s+{re.escape(name)}\s*\("
    m = re.search(pattern, src)
    if not m:
        raise AssertionError(f"Function {name!r} not found in UI source")
    start = m.start()
    depth = 0
    i = src.index("{", start)
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1
    raise AssertionError(f"Could not find closing brace for {name!r}")


class TestFmPfxInitialization(unittest.TestCase):
    """
    Guards the _fmPfx initialization bugs that caused the VVF 9
    'Add Environment' regression:
      1. openEditor() must read eType from the DOM (not from an undeclared 'type')
      2. onTypeChange() must keep _fmPfx in sync whenever the type dropdown changes
    """

    def setUp(self):
        self._src = _load()
        self._open_editor = _extract_function(self._src, "openEditor")
        self._on_type_change = _extract_function(self._src, "onTypeChange")

    def test_open_editor_reads_etype_before_fmPfx_assignment(self):
        """openEditor() must declare `const type = v('eType')` before setting _fmPfx."""
        read_m  = re.search(r"const\s+type\s*=\s*v\s*\(\s*['\"]eType['\"]\s*\)", self._open_editor)
        assign_m = re.search(r"_fmPfx\s*=", self._open_editor)
        self.assertIsNotNone(read_m,  "openEditor() must read eType via v('eType') to initialize _fmPfx")
        self.assertIsNotNone(assign_m, "openEditor() must assign _fmPfx")
        self.assertLess(
            read_m.start(), assign_m.start(),
            "openEditor() must read v('eType') into `type` BEFORE assigning _fmPfx; "
            "using an undeclared `type` resolves to window.type (undefined) and always "
            "sets _fmPfx='vcf9', silently skipping Fleet Manager validation for VVF 9 environments",
        )

    def test_on_type_change_updates_fmPfx(self):
        """onTypeChange() must update _fmPfx so the FM prefix stays in sync with the type dropdown."""
        self.assertRegex(
            self._on_type_change,
            r"_fmPfx\s*=",
            "onTypeChange() must update _fmPfx when the environment-type dropdown changes; "
            "omitting this means _fmPfx is stale after the user switches type in step 0",
        )

    def test_fmPfx_assignment_uses_declared_type(self):
        """_fmPfx must be assigned from a declared local `type` variable, not a bare identifier."""
        body = self._open_editor
        assign_m = re.search(r"_fmPfx\s*=\s*\((\w+)\s*===", body)
        self.assertIsNotNone(assign_m, "Could not find _fmPfx = (... === 'vvf9') in openEditor()")
        var_used = assign_m.group(1)
        # The variable must be declared in the function (const/let/var type = ...)
        declared = re.search(
            rf"(?:const|let|var)\s+{re.escape(var_used)}\s*=",
            body,
        )
        self.assertIsNotNone(
            declared,
            f"openEditor() assigns _fmPfx using `{var_used}` but that variable is not declared "
            "in the function — it resolves to window.type (undefined), always yielding 'vcf9'",
        )


class TestStepBackGuard(unittest.TestCase):
    """
    stepBack() at position 0 would set _editorStep = seq[-1] = undefined, hiding
    all step panels and enabling the Next button, producing 'Please fill in: Name.'
    A pos <= 0 guard must appear before the _editorStep assignment.
    """

    def setUp(self):
        self._src = _load()
        self._step_back = _extract_function(self._src, "stepBack")

    def test_stepback_guards_against_pos_zero(self):
        guard_m  = re.search(r"if\s*\(\s*pos\s*<=?\s*0\s*\)", self._step_back)
        assign_m = re.search(r"_editorStep\s*=\s*seq\s*\[", self._step_back)
        self.assertIsNotNone(guard_m,  "stepBack() must guard against pos <= 0 before assigning _editorStep")
        self.assertIsNotNone(assign_m, "stepBack() must assign _editorStep from seq[]")
        self.assertLess(
            guard_m.start(), assign_m.start(),
            "stepBack() guard must come BEFORE the _editorStep = seq[pos - 1] assignment; "
            "without it, clicking Back on step 0 sets _editorStep = undefined, hides all panels, "
            "and enables the Next button — clicking Next then shows 'Please fill in: Name.'",
        )


class TestRequiredDomIds(unittest.TestCase):
    """
    Critical element IDs referenced in JS must exist in the HTML.
    Missing IDs cause silent null-dereference failures.
    """

    _REQUIRED_IDS = [
        "envEditor", "editorIdx", "editorTitle", "editorStepper",
        "eName", "eType",
        "sp-0", "sp-1", "sp-2", "sp-review",
        "stepBackBtn", "stepNextBtn", "stepSaveBtn",
        "envEditorAlert", "settingsAlert",
        "vcf9-fleetManagerSection", "vvf9-fleetManagerSection",
        "vcf9-vcfOpsServer", "vcf9-vcfOpsUser",
        "vvf9-vcfOpsServer", "vvf9-vcfOpsUser",
        "vcf9-vcfFMServer", "vvf9-vcfFMServer",
        "vvf9-vcenterUser",
        "discoverPassPanel", "discoverUsernamePanel", "discoverResultPanel",
    ]

    def setUp(self):
        self._src = _load()

    def test_all_required_ids_exist(self):
        missing = [
            id_ for id_ in self._REQUIRED_IDS
            if f'id="{id_}"' not in self._src and f"id='{id_}'" not in self._src
        ]
        self.assertEqual(
            missing, [],
            "The following element IDs are referenced in JS but missing from the HTML:\n"
            + "\n".join(f"  {id_}" for id_ in missing),
        )


class TestVvf9StepBlockPresent(unittest.TestCase):
    """
    Each step panel that the VVF 9 flow visits must contain a data-for="vvf9" block.
    Missing blocks cause _showEditorPanels() to show an empty panel.
    """

    def setUp(self):
        self._src = _load()

    def _step_panel_html(self, panel_id: str) -> str:
        m = re.search(rf'id="{re.escape(panel_id)}"', self._src)
        if not m:
            self.fail(f"Panel #{panel_id} not found in HTML")
        start = self._src.rindex("<", 0, m.start())
        depth = 0
        i = start
        while i < len(self._src):
            if self._src[i] == "<":
                tag_close = self._src.index(">", i)
                tag = self._src[i : tag_close + 1]
                if re.match(r"<div\b", tag):
                    depth += 1
                elif tag.startswith("</div"):
                    depth -= 1
                    if depth == 0:
                        return self._src[start : tag_close + 1]
                i = tag_close + 1
            else:
                i += 1
        return self._src[start:]

    def test_sp1_has_vvf9_block(self):
        panel = self._step_panel_html("sp-1")
        self.assertIn(
            'data-for="vvf9"', panel,
            "sp-1 must contain a step-block with data-for=\"vvf9\" for VVF 9 step 1 content",
        )

    def test_sp2_has_vvf9_block(self):
        panel = self._step_panel_html("sp-2")
        self.assertIn(
            'data-for="vvf9"', panel,
            "sp-2 must contain a step-block with data-for=\"vvf9\" for VVF 9 step 2 content",
        )


class TestStepsForSequences(unittest.TestCase):
    """
    Guards the step-sequence contract of _stepsFor().

    _stepsFor() drives wizard navigation, the Back guard, _syncNextButton()
    branching, and _REQUIRED_FIELDS lookups.  Every consumer assumes vcf9
    returns 3 logical steps and all other types return 4.  A change to this
    function without updating those consumers breaks navigation silently.
    """

    def setUp(self):
        self._src = _load()
        self._steps_for = _extract_function(self._src, "_stepsFor")

    def test_vcf9_returns_three_step_sequence(self):
        self.assertRegex(
            self._steps_for,
            r"vcf9.*\[0\s*,\s*1\s*,\s*['\"]review['\"]\s*\]",
            "_stepsFor('vcf9') must return [0, 1, 'review'] — three logical steps. "
            "vcf9 merges credentials and discovery into a single step (step 1) so the "
            "stepper only shows Name/Type → Credentials/Discovery → Review. "
            "Adding a step here without updating _syncNextButton() and _REQUIRED_FIELDS breaks navigation.",
        )

    def test_non_vcf9_returns_four_step_sequence(self):
        self.assertRegex(
            self._steps_for,
            r"\[0\s*,\s*1\s*,\s*2\s*,\s*['\"]review['\"]\s*\]",
            "_stepsFor() must return [0, 1, 2, 'review'] for non-vcf9 types — four logical steps. "
            "All types except vcf9 have a distinct step 2 (vCenter username for vvf9, "
            "vCenter/NSX details for vsphere8). Removing this step collapses two distinct "
            "form panels into one and skips the _REQUIRED_FIELDS check for step 2.",
        )

    def test_vcf9_is_the_only_three_step_type(self):
        # The ternary must branch on 'vcf9' only — no other type should map to 3 steps.
        # This catches accidentally extending the 3-step branch to cover vvf9 or vsphere8.
        m = re.search(r"type\s*===\s*['\"](\w+)['\"]", self._steps_for)
        self.assertIsNotNone(m, "_stepsFor must contain a type === '<type>' branch")
        branched_type = m.group(1)
        self.assertEqual(
            branched_type, "vcf9",
            f"_stepsFor branches on '{branched_type}' for the 3-step path; only 'vcf9' should "
            "receive 3 steps — extending this to vvf9 or vsphere8 hides their step 2 panel.",
        )


class TestSyncNextButtonLogic(unittest.TestCase):
    """
    _syncNextButton() must use the correct condition for step 0 required fields.
    Using _editorStep === 0 ensures only 'eName' is checked; a stale path would
    check type-specific step fields that are hidden, making the button always enabled.
    """

    def setUp(self):
        self._src = _load()
        self._sync = _extract_function(self._src, "_syncNextButton")

    def test_step0_uses_all_key(self):
        self.assertRegex(
            self._sync,
            r"_editorStep\s*===\s*0",
            "_syncNextButton() must branch on _editorStep === 0 to use the 'all' required-field list",
        )

    def test_required_fields_0_all_includes_eName(self):
        m = re.search(r"_REQUIRED_FIELDS\s*=\s*\{(.+?)\}\s*;", self._src, re.DOTALL)
        self.assertIsNotNone(m, "_REQUIRED_FIELDS constant must be defined")
        block = m.group(1)
        self.assertIn(
            "eName", block,
            "_REQUIRED_FIELDS step-0 block must include 'eName' as a required field",
        )


if __name__ == "__main__":
    unittest.main()
