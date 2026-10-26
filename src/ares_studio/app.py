"""ARES Studio GUI: Qt desktop app with bounded background analysis jobs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QSettings, Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import __version__
from .core import Analysis, analyze
from .disassembly import disassemble
from .ghidra import export_functions
from .ollama import explain
from .reporting import make_markdown, write_report

STYLE = """
QWidget { background: #0B1019; color: #DCE6F5; font-family: 'Inter', 'Segoe UI', Arial; font-size: 13px; }
QMainWindow { background: #0B1019; }
QFrame#sidebar { background: #0D1522; border-right: 1px solid #233146; }
QFrame#panel { background: #111D2C; border: 1px solid #26384F; border-radius: 12px; }
QFrame#metric { background: #121F30; border: 1px solid #2A3C56; border-radius: 9px; }
QLabel#muted { color: #8294AD; }
QLabel#overline { color: #6EBBFF; letter-spacing: 2px; font-size: 10px; font-weight: 700; }
QLabel#heading { color: #F2F7FF; font-size: 25px; font-weight: 750; }
QLabel#section { color: #EDF5FF; font-size: 16px; font-weight: 650; }
QLabel#value { color: #F6F9FF; font-size: 19px; font-weight: bold; }
QLabel#logo { color: #79C8FF; font-size: 31px; font-weight: bold; }
QPushButton { padding: 10px 14px; color: #DCE7F8; border-radius: 8px; border: 1px solid #30435C; background: #182639; text-align: center; font-weight: 600; }
QPushButton:hover { background: #233752; border-color: #4876A2; }
QPushButton:disabled { color: #53627A; background: #142030; border-color: #25354A; }
QPushButton#primary { background: #1877D6; border: 1px solid #328FF0; color: white; }
QPushButton#primary:hover { background: #288CEA; }
QPushButton#nav { background: transparent; color: #98ABC3; border: 0; text-align: left; padding: 12px 17px; font-weight: 550; }
QPushButton#nav:checked { color: #FFFFFF; background: #1B3551; border-left: 3px solid #65B5FF; border-radius: 0; }
QPushButton#nav:hover { background: #1B2A3D; }
QPlainTextEdit, QLineEdit, QTableWidget { background: #0D1725; border: 1px solid #2B3D55; border-radius: 7px; color: #D6E5F7; padding: 8px; selection-background-color: #275683; }
QTableWidget { gridline-color: #1E3044; }
QHeaderView::section { background: #172638; color: #8AA1BC; border: 0; border-bottom: 1px solid #30415A; padding: 10px; font-weight: 650; }
QScrollBar:vertical { background: #0E1826; width: 9px; }
QScrollBar::handle:vertical { background: #334C67; border-radius: 4px; min-height: 20px; }
QCheckBox { color: #AEC2D8; }
QProgressBar { background: #152237; border: 0; height: 4px; }
QProgressBar::chunk { background: #50A9F7; }
"""


class Job(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, callback: Callable, parent=None):
        super().__init__(parent)
        self.callback = callback

    def run(self) -> None:
        try:
            self.completed.emit(self.callback())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


def label(text: str, kind: str = "") -> QLabel:
    obj = QLabel(text)
    if kind:
        obj.setObjectName(kind)
    obj.setWordWrap(True)
    return obj


def panel() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("panel")
    box = QVBoxLayout(frame)
    box.setContentsMargins(20, 20, 20, 20)
    box.setSpacing(12)
    return frame, box


def display(text: QPlainTextEdit) -> None:
    mono = QFont("Consolas" if sys.platform == "win32" else "Monospace", 11)
    mono.setStyleHint(QFont.Monospace)
    text.setFont(mono)
    text.setReadOnly(True)
    text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)


def table(headers: list[str]) -> QTableWidget:
    tbl = QTableWidget(0, len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.verticalHeader().setVisible(False)
    tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    tbl.setAlternatingRowColors(True)
    tbl.horizontalHeader().setStretchLastSection(True)
    return tbl


class Studio(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ARES Studio | AI Reverse Engineering")
        self.resize(1360, 860)
        self.setMinimumSize(1030, 690)
        self.analysis: Analysis | None = None
        self.ai_response = ""
        self.functions: list[dict] = []
        self.jobs: set[Job] = set()
        self.settings = QSettings("ARESStudio", "ARESStudio")
        self.nav_items: list[QPushButton] = []
        self._build()
        self._switch(0)
        self.setAcceptDrops(True)

    def _button(self, title: str, action: Callable | None = None, primary: bool = False) -> QPushButton:
        btn = QPushButton(title)
        if primary:
            btn.setObjectName("primary")
        if action:
            btn.clicked.connect(action)
        return btn

    def _build(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(228)
        sidebar = QVBoxLayout(side)
        sidebar.setContentsMargins(15, 25, 15, 20)
        sidebar.setSpacing(6)
        branding = QHBoxLayout()
        branding.addWidget(label("A", "logo"))
        brand = QVBoxLayout()
        brand.addWidget(label("ARES STUDIO", "section"))
        brand.addWidget(label("BINARY INTELLIGENCE", "overline"))
        branding.addLayout(brand)
        branding.addStretch()
        sidebar.addLayout(branding)
        sidebar.addSpacing(30)
        sidebar.addWidget(label("WORKSPACE", "overline"))
        for i, title in enumerate(("Overview", "Strings Explorer", "Disassembly", "Ghidra Analysis", "Local AI Assistant", "Reports & Export")):
            btn = self._button(title, lambda checked=False, idx=i: self._switch(idx))
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setMinimumHeight(42)
            sidebar.addWidget(btn)
            self.nav_items.append(btn)
        sidebar.addStretch()
        sidebar.addWidget(label("LOCAL-FIRST  •  OFFLINE ANALYSIS", "overline"))
        sidebar.addWidget(label(f"Version {__version__}  |  Md Najmul Hossain", "muted"))
        outer.addWidget(side)

        center = QWidget()
        main = QVBoxLayout(center)
        main.setContentsMargins(30, 24, 30, 20)
        main.setSpacing(18)
        top = QHBoxLayout()
        headlines = QVBoxLayout()
        headlines.addWidget(label("REVERSE ENGINEERING WORKSPACE", "overline"))
        self.headline = label("Overview", "heading")
        headlines.addWidget(self.headline)
        self.subtitle = label("Inspect software. Understand behavior. Keep control of your data.", "muted")
        headlines.addWidget(self.subtitle)
        top.addLayout(headlines)
        top.addStretch()
        top.addWidget(self._button("Open binary", self._open, primary=True))
        main.addLayout(top)
        self.pages = QStackedWidget()
        main.addWidget(self.pages, 1)
        self._overview()
        self._strings()
        self._disassembly()
        self._ghidra()
        self._ai()
        self._reports()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0, 0)
        main.addWidget(self.progress)
        footer = QHBoxLayout()
        self.status = label("Ready. No binary loaded.", "muted")
        footer.addWidget(self.status)
        footer.addStretch()
        footer.addWidget(label("READ-ONLY INSPECTION  /  ZERO TELEMETRY", "overline"))
        main.addLayout(footer)
        outer.addWidget(center, 1)
        menu = self.menuBar().addMenu("File")
        op = QAction("Open binary", self)
        op.setShortcut("Ctrl+O")
        op.triggered.connect(self._open)
        menu.addAction(op)
        exp = QAction("Export report", self)
        exp.setShortcut("Ctrl+S")
        exp.triggered.connect(self._export)
        menu.addAction(exp)

    def _overview(self) -> None:
        page = QWidget()
        box = QVBoxLayout(page)
        box.setSpacing(20)
        metrics = QGridLayout()
        self.stats: dict[str, QLabel] = {}
        for i, (key, title) in enumerate((("format", "FILE FORMAT"), ("architecture", "ARCHITECTURE"),
                                          ("size", "BINARY SIZE"), ("entropy", "SAMPLED ENTROPY"))):
            p = QFrame()
            p.setObjectName("metric")
            layout = QVBoxLayout(p)
            layout.setContentsMargins(18, 16, 18, 16)
            layout.addWidget(label(title, "overline"))
            value = label("—", "value")
            layout.addWidget(value)
            self.stats[key] = value
            metrics.addWidget(p, 0, i)
        box.addLayout(metrics)
        overview, layout = panel()
        layout.addWidget(label("Binary assessment", "section"))
        layout.addWidget(label("Locally collected metadata. Indicators are hypotheses, not malware verdicts.", "muted"))
        self.overview_text = QPlainTextEdit()
        display(self.overview_text)
        self.overview_text.setPlainText("Start by opening a PE, ELF, Mach-O, or unknown binary.\n\n"
                                        "ARES does not execute the file. Your data stays on your machine.\n\n"
                                        "Capabilities: binary headers, entry point, sections, sample entropy, strings, "
                                        "optional Capstone disassembly, Ghidra decompilation, and local Ollama explanations.")
        layout.addWidget(self.overview_text)
        box.addWidget(overview, 1)
        self.pages.addWidget(page)

    def _strings(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        top, top_layout = panel()
        top_layout.addWidget(label("Extracted printable strings", "section"))
        top_layout.addWidget(label("Bounded scan, first 16 MiB. A string's presence does not prove execution.", "muted"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter extracted strings...")
        self.search.textChanged.connect(self._filter_strings)
        top_layout.addWidget(self.search)
        self.string_table = table(["#", "String value"])
        self.string_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        top_layout.addWidget(self.string_table, 1)
        layout.addWidget(top, 1)
        self.pages.addWidget(page)

    def _disassembly(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        p, body = panel()
        body.addWidget(label("Entry-point disassembly", "section"))
        body.addWidget(label("Uses optional Capstone. This is a static entry-point window, not full control-flow analysis.", "muted"))
        body.addWidget(self._button("Disassemble entry point", self._run_disassembly, primary=True))
        self.disasm_text = QPlainTextEdit()
        display(self.disasm_text)
        self.disasm_text.setPlainText("Load a binary, then select Disassemble entry point.")
        body.addWidget(self.disasm_text, 1)
        layout.addWidget(p, 1)
        self.pages.addWidget(page)

    def _ghidra(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        p, body = panel()
        body.addWidget(label("Ghidra headless integration", "section"))
        body.addWidget(label("Optional. Requires Ghidra installed separately. Runs Ghidra's analysis engine "
                             "on the selected file with a disposable project.", "muted"))
        controls = QHBoxLayout()
        self.ghidra_folder = QLineEdit(str(self.settings.value("ghidra_folder", "")))
        self.ghidra_folder.setPlaceholderText("Path to installed Ghidra directory")
        controls.addWidget(self.ghidra_folder, 1)
        controls.addWidget(self._button("Browse", self._browse_ghidra))
        body.addLayout(controls)
        self.ghidra_ack = QCheckBox("I trust this Ghidra installation and understand its analyzer will process an untrusted file")
        body.addWidget(self.ghidra_ack)
        body.addWidget(self._button("Run decompilation", self._run_ghidra, primary=True))
        self.functions_table = table(["Address", "Function"])
        self.functions_table.itemSelectionChanged.connect(self._select_function)
        self.ghidra_code = QPlainTextEdit()
        display(self.ghidra_code)
        self.ghidra_code.setPlainText("Decompiled functions appear here after Ghidra analysis.")
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.functions_table)
        split.addWidget(self.ghidra_code)
        body.addWidget(split, 1)
        layout.addWidget(p, 1)
        self.pages.addWidget(page)

    def _ai(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        p, body = panel()
        body.addWidget(label("Private AI explanation", "section"))
        body.addWidget(label("Local Ollama only (loopback address). No cloud API, account, or remote upload.", "muted"))
        row = QHBoxLayout()
        self.model = QLineEdit(str(self.settings.value("model", "qwen2.5-coder:7b")))
        self.model.setPlaceholderText("Installed Ollama model")
        self.endpoint = QLineEdit(str(self.settings.value("endpoint", "http://127.0.0.1:11434")))
        self.endpoint.setPlaceholderText("http://127.0.0.1:11434")
        row.addWidget(label("MODEL"))
        row.addWidget(self.model, 1)
        row.addWidget(label("ENDPOINT"))
        row.addWidget(self.endpoint, 1)
        body.addLayout(row)
        body.addWidget(self._button("Explain current binary", self._run_ai, primary=True))
        self.ai_text = QPlainTextEdit()
        display(self.ai_text)
        self.ai_text.setPlainText("Load a binary, install/run Ollama locally, then request an explanation.\n"
                                  "AI output is not evidence. Always validate observations independently.")
        body.addWidget(self.ai_text, 1)
        layout.addWidget(p, 1)
        self.pages.addWidget(page)

    def _reports(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        p, body = panel()
        body.addWidget(label("Reproducible analysis report", "section"))
        body.addWidget(label("Save JSON for machines or Markdown for investigators. "
                             "Reports may include sensitive file paths and extracted strings.", "muted"))
        controls = QHBoxLayout()
        controls.addWidget(self._button("Export JSON", lambda: self._export(".json"), primary=True))
        controls.addWidget(self._button("Export Markdown", lambda: self._export(".md")))
        controls.addStretch()
        body.addLayout(controls)
        self.report_preview = QPlainTextEdit()
        display(self.report_preview)
        self.report_preview.setPlainText("Open a binary to preview a report.")
        body.addWidget(self.report_preview, 1)
        layout.addWidget(p, 1)
        self.pages.addWidget(page)

    def _switch(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav_items):
            button.setChecked(i == index)
        self.headline.setText(("Overview", "Strings Explorer", "Disassembly", "Ghidra Analysis",
                               "Local AI Assistant", "Reports & Export")[index])

    def _open(self) -> None:
        file, _ = QFileDialog.getOpenFileName(self, "Select binary for read-only analysis")
        if file:
            self.load_file(file)

    def load_file(self, path: str) -> None:
        self._job("Inspecting file without execution...", lambda: analyze(path), self._loaded)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls() and len(event.mimeData().urls()) == 1 and event.mimeData().urls()[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        url = event.mimeData().urls()[0]
        if url.isLocalFile():
            self.load_file(url.toLocalFile())

    def _job(self, title: str, action: Callable, done: Callable) -> None:
        if self.jobs:
            QMessageBox.information(self, "Analysis running", "Finish the current task before starting another.")
            return
        self.status.setText(title)
        self.progress.setVisible(True)
        worker = Job(action, self)
        self.jobs.add(worker)
        worker.completed.connect(done)
        worker.failed.connect(self._error)
        worker.finished.connect(lambda job=worker: self._job_finished(job))
        worker.start()

    def _job_finished(self, worker: Job) -> None:
        self.jobs.discard(worker)
        worker.deleteLater()
        self.progress.setVisible(False)

    def _error(self, message: str) -> None:
        self.status.setText("Task failed. See message.")
        QMessageBox.warning(self, "ARES Studio", message)

    def _loaded(self, result: Analysis) -> None:
        self.analysis = result
        self.ai_response = ""
        self.functions = []
        self.stats["format"].setText(result.file_type)
        self.stats["architecture"].setText(result.architecture)
        self.stats["size"].setText(f"{result.size / 1024:,.1f} KiB")
        self.stats["entropy"].setText(f"{result.entropy:.2f} / 8")
        info = [f"FILE          {result.name}", f"SHA-256       {result.sha256}",
                f"TYPE          {result.file_type}", f"ARCH          {result.architecture}",
                f"ENTRY         {hex(result.entry_point) if result.entry_point is not None else 'unknown'}",
                f"FILE OFFSET   {hex(result.entry_offset) if result.entry_offset is not None else 'unknown'}",
                f"SECTIONS      {len(result.sections)}", f"STRINGS       {len(result.strings)}", "",
                "OBSERVATIONS"]
        info.extend(f"• {i}" for i in result.indicators or ["No heuristic indicators found"])
        info.extend(["", "SECTIONS"])
        info.extend(f"{s.name:20} off={s.offset:>10,}  size={s.size:>10,} "
                    f"exec={'yes' if s.executable else 'no'}" for s in result.sections)
        info.extend(["", "NOTES"])
        info.extend(f"• {w}" for w in result.warnings or ["Complete sampled inspection"])
        self.overview_text.setPlainText("\n".join(info))
        self._filter_strings()
        self.disasm_text.setPlainText("Click Disassemble entry point to inspect machine instructions.")
        self.ghidra_code.setPlainText("Run optional Ghidra analysis to populate this view.")
        self.functions_table.setRowCount(0)
        self.ai_text.setPlainText("Click Explain current binary for a local-only interpretation.")
        self._update_report()
        self.status.setText(f"Loaded {result.name}; read-only static inspection complete.")
        self._switch(0)

    def _filter_strings(self) -> None:
        if not self.analysis:
            return
        needle = self.search.text().casefold()
        strings = [(i, value) for i, value in enumerate(self.analysis.strings, 1) if needle in value.casefold()]
        self.string_table.setRowCount(len(strings))
        for r, (n, text) in enumerate(strings):
            self.string_table.setItem(r, 0, QTableWidgetItem(str(n)))
            self.string_table.setItem(r, 1, QTableWidgetItem(text))

    def _run_disassembly(self) -> None:
        if self._needs_file():
            self._job("Disassembling entry-point window...", lambda: disassemble(self.analysis), self._disassembled)

    def _disassembled(self, rows: list[dict]) -> None:
        self.disasm_text.setPlainText("\n".join(f"{r['address']:>18}  {r['bytes']:<32} {r['instruction']}"
                                                    for r in rows) or "No valid instructions decoded.")
        self.status.setText(f"Disassembled {len(rows)} instructions (static only).")
        self._switch(2)

    def _browse_ghidra(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Ghidra installation root")
        if folder:
            self.ghidra_folder.setText(folder)

    def _run_ghidra(self) -> None:
        if not self._needs_file():
            return
        if not self.ghidra_ack.isChecked():
            QMessageBox.warning(self, "Approval required", "Confirm the Ghidra analysis safety acknowledgment first.")
            return
        folder = self.ghidra_folder.text().strip()
        if not folder:
            self._error("Select a local Ghidra installation directory")
            return
        self.settings.setValue("ghidra_folder", folder)
        self._job("Running local Ghidra headless analysis...", lambda: export_functions(self.analysis, folder), self._ghidra_done)

    def _ghidra_done(self, functions: list[dict]) -> None:
        self.functions = functions
        self.functions_table.setRowCount(len(functions))
        for i, record in enumerate(functions):
            self.functions_table.setItem(i, 0, QTableWidgetItem(str(record.get("address", ""))))
            self.functions_table.setItem(i, 1, QTableWidgetItem(str(record.get("name", ""))))
        self._update_report()
        self.status.setText(f"Ghidra exported {len(functions)} functions.")
        self._switch(3)
        if functions:
            self.functions_table.selectRow(0)

    def _select_function(self) -> None:
        selected = self.functions_table.selectedItems()
        if selected:
            row = selected[0].row()
            if row < len(self.functions):
                record = self.functions[row]
                self.ghidra_code.setPlainText(str(record.get("decompiled", "")) or "No decompilation returned.")

    def _run_ai(self) -> None:
        if not self._needs_file():
            return
        name, url = self.model.text().strip(), self.endpoint.text().strip()
        self.settings.setValue("model", name)
        self.settings.setValue("endpoint", url)
        context = "\n".join(f"{x.get('name')}: {x.get('decompiled', '')[:350]}" for x in self.functions[:15])
        self._job("Querying installed local Ollama model...", lambda: explain(self.analysis, name, url, context), self._ai_done)

    def _ai_done(self, text: str) -> None:
        self.ai_response = text
        self.ai_text.setPlainText(text)
        self._update_report()
        self.status.setText("Local AI response ready. Verify all interpretations.")
        self._switch(4)

    def _update_report(self) -> None:
        if self.analysis:
            self.report_preview.setPlainText(make_markdown(self.analysis, self.ai_response, self.functions))

    def _needs_file(self) -> bool:
        if not self.analysis:
            QMessageBox.information(self, "Open binary", "Select a binary first (File → Open binary).")
            return False
        return True

    def _export(self, forced_ext: str = "") -> None:
        if not self._needs_file():
            return
        suggested = Path(self.analysis.name).stem + "-ares-report" + (forced_ext or ".json")
        chosen, _ = QFileDialog.getSaveFileName(self, "Export report", suggested,
                                                "JSON (*.json);;Markdown (*.md)")
        if chosen:
            try:
                if Path(chosen).suffix.lower() not in (".json", ".md"):
                    chosen += forced_ext or ".json"
                write_report(chosen, self.analysis, self.ai_response, self.functions)
                self.status.setText(f"Saved report: {chosen}")
            except OSError as exc:
                self._error(str(exc))


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName("ARES Studio")
    application.setOrganizationName("ARESStudio")
    application.setStyle("Fusion")
    application.setStyleSheet(STYLE)
    ico = Path(__file__).parent / "resources" / "ares.svg"
    if ico.exists():
        application.setWindowIcon(QIcon(str(ico)))
    window = Studio()
    window.show()
    return application.exec()


if __name__ == "__main__":
    sys.exit(main())
