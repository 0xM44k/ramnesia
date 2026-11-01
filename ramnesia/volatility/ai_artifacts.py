"""
Volatility 3 plugin: ramnesia.ai_artifacts

Scans each process's memory for AI/agent artifacts using the same detector
engine as the standalone CLI. Drop this file into a directory on Volatility 3's
plugin path, e.g.:

    vol -p ./ramnesia/volatility windows.ramnesia.AiArtifacts
    vol -p ./ramnesia/volatility linux.ramnesia.AiArtifacts

It degrades gracefully: if volatility3 is not installed, importing this module
raises a clear error instead of a confusing traceback.

NOTE: tested design against Volatility 3 2.x APIs; run on your Linux/DFIR box
where volatility3 and a real memory image are available.
"""
from __future__ import annotations

import importlib.util
from typing import Iterable

# Make the core engine importable whether or not the package is installed.
try:
    from ramnesia.patterns import detectors_for
    from ramnesia.scanner import scan_bytes
except Exception:  # pragma: no cover - fallback when run from Volatility's loader
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from ramnesia.patterns import detectors_for
    from ramnesia.scanner import scan_bytes

if importlib.util.find_spec("volatility3") is None:  # pragma: no cover
    raise ImportError(
        "volatility3 is required to run this plugin. Install it on your DFIR host "
        "(pip install volatility3) and run via `vol -p <this dir> ...`."
    )

from volatility3.framework import interfaces, renderers  # noqa: E402
from volatility3.framework.configuration import requirements  # noqa: E402
from volatility3.framework.renderers import format_hints  # noqa: E402
from volatility3.plugins.windows import pslist  # noqa: E402

CHUNK = 4 * 1024 * 1024


class AiArtifacts(interfaces.plugins.PluginInterface):
    """Carve AI/agent artifacts (prompts, API keys, MCP calls) from process memory."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.PluginRequirement(name="pslist", plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(
                name="categories", element_type=str, optional=True,
                description="limit to categories: secret prompt mcp model",
            ),
            requirements.IntRequirement(
                name="pid", description="scan only this PID", optional=True,
            ),
        ]

    def _scan_proc(self, proc, detectors) -> Iterable:
        try:
            proc_layer_name = proc.add_process_layer()
        except Exception:
            return
        layer = self.context.layers[proc_layer_name]
        pid = int(proc.UniqueProcessId)
        name = proc.ImageFileName.cast(
            "string", max_length=proc.ImageFileName.vol.count, errors="replace"
        )
        for offset, size, _mapped_off, _mapped_size, _lname in layer.mapping(0x0, layer.maximum_address, ignore_errors=True):
            read = 0
            while read < size:
                take = min(CHUNK, size - read)
                try:
                    data = layer.read(offset + read, take, pad=True)
                except Exception:
                    break
                for f in scan_bytes(data, detectors, base_offset=offset + read):
                    yield (pid, name, f)
                read += take

    def _generator(self):
        cats = self.config.get("categories", None)
        only_pid = self.config.get("pid", None)
        detectors = detectors_for(list(cats) if cats else None)
        kernel = self.context.modules[self.config["kernel"]]
        for proc in pslist.PsList.list_processes(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            if only_pid is not None and int(proc.UniqueProcessId) != only_pid:
                continue
            for pid, name, f in self._scan_proc(proc, detectors):
                yield (0, (
                    pid, str(name), f.category, f.severity, f.detector,
                    format_hints.Hex(f.offset), f.match, f.context,
                ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int), ("Process", str), ("Category", str), ("Severity", str),
                ("Detector", str), ("Offset", format_hints.Hex), ("Match", str), ("Context", str),
            ],
            self._generator(),
        )
