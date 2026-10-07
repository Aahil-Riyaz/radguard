"""Mutation testing: change the code in small ways and check that the tests notice.

Coverage says a line ran; it does not say any test would fail if the line were
wrong. This tool makes one small change at a time (a "mutant"): flip a
comparison (< to <=, == to !=), swap and/or, swap + and -, bump an integer
constant, drop a `not`, delete a `raise`. It runs the test suite against each
mutant in an isolated copy of the repository. A mutant the tests do not catch
"survives", and every survivor is either a missing test or a provably
equivalent change.

Lines marked `# pragma: no mutate` are skipped: tuning constants (a budget of
1 GiB or 1 GiB + 1 byte behaves the same) and display text. The report counts
them, so the score cannot be inflated quietly. Before mutating, the harness
checks that the suite still passes on an unparsed-but-unchanged copy of every
target file; otherwise tests that depend on source formatting would produce
fake kills.

    python scripts/mutation_test.py src/radguard/codecs.py [more files] [--workers N]
"""

from __future__ import annotations

import argparse
import ast
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPY = ("src", "tests", "scripts", "examples", "docs", "pyproject.toml")
SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}
ARITHMETIC: dict[type[ast.operator], type[ast.operator]] = {ast.Add: ast.Sub, ast.Sub: ast.Add}


@dataclass(frozen=True)
class Mutant:
    path: str  # relative to the repository root
    index: int  # n-th mutation point in the file, in AST walk order
    line: int
    description: str


class Mutator(ast.NodeTransformer):
    """Enumerates mutation points; with `target` set, applies exactly that one."""

    def __init__(self, target: int | None = None, skip_lines: frozenset[int] = frozenset()):
        self.target = target
        self.skip_lines = skip_lines
        self.points: list[tuple[int, str]] = []
        self._exempt: set[int] = set()

    def _point(self, node: ast.AST, description: str) -> bool:
        if getattr(node, "lineno", 0) in self.skip_lines:
            return False
        self.points.append((getattr(node, "lineno", 0), description))
        return len(self.points) - 1 == self.target

    def visit_Module(self, node: ast.Module) -> ast.AST:
        for owner in ast.walk(node):
            if isinstance(owner, (ast.Module, ast.FunctionDef, ast.ClassDef)) and owner.body:
                first = owner.body[0]  # docstrings are not behaviour
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    self._exempt.add(id(first.value))
            if isinstance(owner, (ast.FunctionDef, ast.ClassDef)):  # decorators configure, they do not compute
                self._exempt.update(id(n) for d in owner.decorator_list for n in ast.walk(d))
        return self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        for i, op in enumerate(node.ops):
            new = SWAPS.get(type(op))
            if new and self._point(node, f"{type(op).__name__} -> {new.__name__}"):
                node.ops[i] = new()
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        new = ast.Or if isinstance(node.op, ast.And) else ast.And
        if self._point(node, f"{type(node.op).__name__} -> {new.__name__}"):
            node.op = new()
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self._point(node, "remove not"):
            return node.operand
        return node

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        self.generic_visit(node)
        new = ARITHMETIC.get(type(node.op))
        if new and self._point(node, f"{type(node.op).__name__} -> {new.__name__}"):
            node.op = new()
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if id(node) in self._exempt:
            return node
        if isinstance(node.value, bool):
            if self._point(node, f"{node.value} -> {not node.value}"):
                return ast.copy_location(ast.Constant(not node.value), node)
        elif isinstance(node.value, int) and self._point(node, f"{node.value} -> {node.value + 1}"):
            return ast.copy_location(ast.Constant(node.value + 1), node)
        return node

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return node  # message text and format specs are not behaviour

    def visit_Raise(self, node: ast.Raise) -> ast.AST:
        self.generic_visit(node)
        if self._point(node, "remove raise"):
            return ast.copy_location(ast.Pass(), node)
        return node


def pragma_lines(source: str) -> frozenset[int]:
    return frozenset(n for n, line in enumerate(source.splitlines(), 1) if "pragma: no mutate" in line)


def mutants_of(path: str) -> list[Mutant]:
    source = (ROOT / path).read_text(encoding="utf-8")
    mutator = Mutator(skip_lines=pragma_lines(source))
    mutator.visit(ast.parse(source))
    return [Mutant(path, i, line, desc) for i, (line, desc) in enumerate(mutator.points)]


def mutated_source(mutant: Mutant) -> str:
    source = (ROOT / mutant.path).read_text(encoding="utf-8")
    tree = Mutator(target=mutant.index, skip_lines=pragma_lines(source)).visit(ast.parse(source))
    return ast.unparse(ast.fix_missing_locations(tree))


def formatting_independent(files: list[str]) -> bool:
    """Do the tests still pass when every target file is unparsed but not mutated?"""
    with tempfile.TemporaryDirectory(prefix="radguard-unparse-") as tmp:
        work = Path(tmp)
        for name in COPY:
            src = ROOT / name
            (shutil.copytree if src.is_dir() else shutil.copy2)(src, work / name)
        for path in files:
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
            (work / path).write_text(ast.unparse(tree), encoding="utf-8")
        run = subprocess.run(test_command(), cwd=work, capture_output=True, text=True,
                             env={**os.environ, "HYPOTHESIS_PROFILE": "quick"})
        if run.returncode != 0:
            print(run.stdout[-3000:])
        return run.returncode == 0


def test_command() -> list[str]:
    # The repository hygiene test checks source style (ASCII, line length), which every
    # unparsed mutant changes by construction; it would kill mutants for the wrong reason.
    return [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
            "--ignore=tests/test_repo_hygiene.py"]


def worker(jobs: queue.Queue[Mutant], results: list[tuple[Mutant, str]], timeout: float) -> None:
    with tempfile.TemporaryDirectory(prefix="radguard-mutants-") as tmp:
        work = Path(tmp)
        for name in COPY:
            src = ROOT / name
            (shutil.copytree if src.is_dir() else shutil.copy2)(src, work / name)
        env = {**os.environ, "HYPOTHESIS_PROFILE": "quick"}
        while True:
            try:
                mutant = jobs.get_nowait()
            except queue.Empty:
                return
            target = work / mutant.path
            original = target.read_text(encoding="utf-8")
            target.write_text(mutated_source(mutant), encoding="utf-8")
            try:
                run = subprocess.run(test_command(), cwd=work, env=env, capture_output=True, timeout=timeout)
                outcome = "survived" if run.returncode == 0 else "killed"
            except subprocess.TimeoutExpired:
                outcome = "killed (timeout)"  # the mutant made something hang, and the tests' time limit caught it
            finally:
                target.write_text(original, encoding="utf-8")
            results.append((mutant, outcome))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    args = parser.parse_args()

    started = time.monotonic()
    baseline = subprocess.run(test_command(), cwd=ROOT, capture_output=True,
                              env={**os.environ, "HYPOTHESIS_PROFILE": "quick"})
    if baseline.returncode != 0:
        print("the test suite fails without mutations; fix that first")
        return 2
    timeout = max(60.0, 4 * (time.monotonic() - started))
    files = [Path(f).as_posix() for f in args.files]
    if not formatting_independent(files):
        print("tests depend on the source formatting of a target file; mutants would be killed for the wrong reason")
        return 2
    skipped = sum(len(pragma_lines((ROOT / f).read_text(encoding="utf-8"))) for f in files)

    jobs: queue.Queue[Mutant] = queue.Queue()
    total = 0
    for path in args.files:
        for mutant in mutants_of(Path(path).as_posix()):
            jobs.put(mutant)
            total += 1
    results: list[tuple[Mutant, str]] = []
    threads = [threading.Thread(target=worker, args=(jobs, results, timeout)) for _ in range(args.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for path in args.files:
        mine = [(m, o) for m, o in results if m.path == Path(path).as_posix()]
        killed = sum(o != "survived" for _, o in mine)
        print(f"{path}: {killed}/{len(mine)} mutants killed ({100 * killed / max(1, len(mine)):.1f}%)")
    survivors = sorted((m for m, o in results if o == "survived"), key=lambda m: (m.path, m.line))
    lines = {p: (ROOT / p).read_text(encoding="utf-8").splitlines() for p in {m.path for m in survivors}}
    for m in survivors:
        print(f"  SURVIVED {m.path}:{m.line}  {m.description:<22} | {lines[m.path][m.line - 1].strip()[:90]}")
    killed = sum(o != "survived" for _, o in results)
    print(f"\ntotal: {killed}/{total} killed ({100 * killed / max(1, total):.1f}%) "
          f"in {time.monotonic() - started:.0f}s with {args.workers} workers; "
          f"{skipped} lines exempt via '# pragma: no mutate'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
