"""Golden-baseline drift detection for agent repositories.

The modules ``baseline``, ``manifest``, ``snapshot``, ``checks``, ``engine`` and
``cli`` depend only on the standard library and PyYAML. They are vendored
byte-for-byte into the golden baseline's composite GitHub Action, so keep them
free of ADCM imports. ADCM-only integration lives in ``integration`` and
``issues``.
"""

ENGINE_VERSION = "1.0.0"
