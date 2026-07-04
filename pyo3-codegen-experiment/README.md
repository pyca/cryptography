# Experiment: shrinking PyO3's macro-generated code to speed up cryptography-rust builds

This directory documents an experiment that modified PyO3 v0.29.0 to reduce the
amount of code its attribute macros generate, and quantifies the effect on
`cryptography-rust`'s build time. The PyO3 changes are provided in two forms:

- `pyo3-codegen-slim.patch` — plain diff against the `v0.29.0` tag (what the
  measurements below were taken with).
- `0001-Reduce-macro-generated-code-size.patch` — the same change rebased onto
  PyO3 `main` (commit `90d63e8c`, 2026-07-04) as a `git am`-able mailbox patch.
  The rebase was conflict-free and the reduction is unchanged (probe crate:
  351 → 242 expanded lines on both v0.29.0 and main). To put it on a branch:

  ```sh
  git clone https://github.com/PyO3/pyo3.git && cd pyo3
  git checkout -b codegen-slim origin/main
  git am /path/to/0001-Reduce-macro-generated-code-size.patch
  ```

  On main + patch, PyO3's own test suite status is identical to the v0.29.0
  validation described below: all lib and integration tests pass except 3
  pre-existing `OsStr`/`Path` failures caused by this container's ASCII
  filesystem encoding (they fail identically on pristine checkouts), and the
  UI-test diagnostic snapshots need re-blessing (the `ui_test` harness also
  wants inline annotation updates, which are best done by hand upstream).

## Headline results

Measured on the leaf crate `cryptography-rust` (25,711 source lines; 119
`#[pyclass]`, 107 `#[pymethods]` blocks, 92 `#[pyfunction]`, 29 declarative
`#[pymodule]`), rustc 1.94.1, 4-core Linux container, CPython 3.11, abi3:

| Metric (median)                                        | stock 0.29.0 | patched | Δ |
|--------------------------------------------------------|--------------|---------|-----|
| Macro-expanded size (`-Zunpretty=expanded`, lines)      | 84,975       | 67,069  | **−21.1%** |
| …of which pyo3-generated (excl. ~25.7k user lines)      | ~59,300      | ~41,300 | **−30%** |
| Debug touch-rebuild of leaf, incremental (7 runs)       | 2.84 s       | 2.53 s  | **−11.0%** |
| Debug rebuild of leaf, non-incremental (4 runs)         | 10.31 s      | 9.59 s  | **−6.9%** |
| rustc total CPU for leaf (`-Ztime-passes`, non-incr.)   | 10.30 s      | 9.41 s  | **−8.6%** |
| Release rebuild of leaf, non-incremental (3 runs)       | 18.85 s      | 18.45 s | −2.1% |

Timing protocol: all dependencies pre-built, `touch src/rust/src/lib.rs`, then
`cargo build -p cryptography-rust` timed wall-clock; medians reported, first
run after a cache flip discarded.

So: generated code shrinks by roughly a third, debug rebuilds of the leaf get
~7–11% faster. Release builds barely move because release time is dominated by
LLVM optimizing the user code itself; the macro glue is small and gets inlined
away either way. The debug frontend+backend saving tracks the expansion
reduction sub-linearly because a large share of compile time is the 25.7k
lines of real crate code, which is untouched.

Per-construct expansion cost (minimal probe crate):

| Construct                              | stock | patched |
|----------------------------------------|-------|---------|
| bare `#[pyclass]` struct               | 115   | 78      |
| pyclass + `#[new]` + 2 methods + getter| 351   | 242     |
| `#[pyfunction]` (2 args)               | 96    | 64      |
| + declarative `#[pymodule]` export     | 128   | 96      |

Per-category, in cryptography-rust's expansion:

| Category                       | stock  | patched | Δ |
|--------------------------------|--------|---------|------|
| 760 `__pymethod_*` wrappers    | 27,704 | 16,949  | −39% |
| 133 `PyClassImpl` impls        | 10,694 | 8,519   | −20% |
| 96 `PyMethods` items arrays    | 6,986  | 6,644   | −5%  |
| 77 `__pyfunction_*` wrappers   | 4,808  | 2,595   | −46% |
| 146 `PyTypeInfo` impls         | 2,032  | 1,500   | −26% |
| 108 `IntoPyObject` impls       | 1,973  | 1,433   | −27% |

## What was changed in PyO3

All changes keep the same runtime call graph after inlining; every new helper
is `#[inline]` and replaces code that was previously emitted inline at each
expansion site. In rough order of impact:

1. **Fused return-value conversion.** The two-step autoref-specialization
   dance (`converter(&obj).wrap(obj).map_err(...)` followed by
   `converter(&result).map_into_ptr(py, result)`, ~12 expanded lines per
   method) is now a single `converter(&ret).wrap_into_ptr(py, ret)` call. New
   methods were added at each level of the existing converter ladder
   (`EmptyTupleConverter`, `IntoPyObjectConverter`, plus `unreachable!`
   mirrors on the unknown-type levels for diagnostics), so `-> ()`,
   `-> T`, `-> Result<(), E>` and `-> Result<T, E>` all specialize exactly as
   before.

2. **Fused required-argument extraction.**
   `extract_argument(unsafe { unwrap_required_argument(output[i]) }, &mut h, "name")`
   became `unsafe { extract_required_argument(output[i], &mut h, "name") }?`
   (plus a `from_py_with_required` twin).

3. **Fused receiver extraction.** The trusted self-cast no longer nests two
   `unsafe` blocks, and `TryFrom<&Bound<T>>`-style receivers (`PyRef`, `Py`,
   `Bound` receivers — 119 sites in this crate) go through new
   `extract_receiver[_trusted]` helpers instead of a ~10-line
   `Ok(cast?)…and_then(TryFrom…)` chain.

4. **Smaller wrapper preambles.** Argument holders are declared with a
   single tuple pattern (`let (mut h0, mut h1, …) = (INIT, INIT, …);`)
   instead of one `let` plus a clippy `allow` each, and the vestigial
   per-argument `use …::Probe as _;` import was dropped entirely (nothing in
   the non-`experimental-inspect` argument path references a probe; verified
   against PyO3's full test suite). An earlier revision of this patch also
   emitted short module aliases (`use …::extract_argument as _e;`) to shrink
   pretty-printed paths; that turned out to be worth only ~50 expanded lines
   crate-wide once the fused helpers landed, and was dropped for
   readability (likewise a `_t` alias inside `get_trampoline_function!`,
   worth ~30 lines).

5. **`PyClassImpl` slimming.** `MODULE` and `RAW_DOC` gained trait-level
   defaults, so the macro emits `MODULE`/`RAW_DOC`/`IS_BASETYPE`/`IS_SUBCLASS`/
   `IS_MAPPING`/`IS_SEQUENCE`/`IS_IMMUTABLE_TYPE` only when they differ from
   the default. Classes with no intrinsic items reference one shared
   `NO_PY_CLASS_ITEMS` static instead of a per-class empty static. Empty
   generated `impl Cls {}` blocks and empty assertion consts are skipped.

6. **Class docstring assembly moved to type-object creation.** Instead of
   emitting a per-class const-eval concatenation (`combined_len` +
   `combine_to_array::<LEN>` monomorphized per class), the macro now emits
   only `DOC_PIECES: &[&[u8]]` (still using the compile-time
   `HasNewTextSignature` probe, which cannot move into generic code), and
   `create_type_object` concatenates the pieces once per class at Python type
   creation. That is a one-time, import-time cost of well under a
   microsecond per class (CPython copies `tp_doc` out of the spec anyway);
   steady-state runtime is untouched.

7. **Misc.** `type_object_raw` outlined into `pyclass_type_object_raw::<T>`;
   `FunctionDescription::new`/`KeywordOnlyParameterDescription::new` const
   constructors instead of struct literals; `IntoPyObject` impls emitted with
   `Bound<'py, Self>`/`PyResult<Self::Output>` instead of
   `<Self as IntoPyObject>::…` projections; trampoline shims use short
   re-exports (`fastcall_kw`, `cfunc_kw`); the `HasAutomaticFromPyObject`
   deprecation probe const (8 lines + const-eval per class) was removed; the
   `let result = …; result` wrapper tail and a stray `;` in `#[new]` were
   dropped.

## What can't be shrunk (and why)

- **One trampoline per method is irreducible.** CPython's `PyMethodDef.ml_meth`
  carries no closure pointer, so every method needs a distinct
  `extern "C"` symbol. (Getters/setters already share one trampoline because
  `PyGetSetDef` has a `closure` field.)
- **The `struct Def; impl MethodDef… trampoline::<Def>` shim** exists because
  stable Rust doesn't allow function pointers as const generics. It was
  shortened but not eliminated. Folding the trampoline into the wrapper fn
  itself (making `__pymethod_*` the `extern "C"` symbol, with the panic-catch
  logic as a generic wrapper around a closure) would remove the shims
  entirely (est. another ~4–5k lines here) but is a larger restructuring —
  left as future work.
- **Associated types (`Layout`, `BaseNativeType`, `PyClassMutability`, …)**
  are formulaic per class but can't get trait defaults on stable
  (associated-type defaults are unstable), and removing them from the trait
  would strip bounds ~29 internal use sites rely on.

## Behavior differences (all deliberate, none affect cryptography)

- Error types used in `-> Result<T, E>` must satisfy `PyErr: From<E>` rather
  than `E: Into<PyErr>`; only a hand-written `Into<PyErr>` without a
  matching `From` impl would notice.
- On PyPy only, a receiver-cast failure in a slot method using
  `ExtractErrorMode::NotImplemented` now falls back to `NotImplemented` like
  `TryFrom` receiver failures always have, instead of raising immediately.
  (On CPython the trusted cast cannot fail.)
- The deprecation warning for automatic `FromPyObject` via `Clone` is no
  longer emitted.
- `PyClassImpl::DOC` (semi-private `impl_` API) is replaced by `DOC_PIECES`.
- Compile-error snapshots differ: PyO3's trybuild UI tests show reworded /
  occasionally extra cascade errors on *invalid* code (all cases still fail
  to compile); snapshots would need re-blessing upstream.

## Validation

- PyO3's own test suite at v0.29.0 + patch: 834 lib tests pass and all
  integration-test targets pass, except (a) 3 `OsStr`/`Path` conversion tests
  that fail identically on *pristine* v0.29.0 in this container, and (b) the
  23 UI-snapshot text diffs described above.
- `nox -e tests-nocoverage` for cryptography: **3909 passed, 648 skipped** —
  byte-for-byte the same counts with stock and patched PyO3.
- Runtime microbenchmarks (hash create/update/finalize, x509 getter, method
  call with args, PEM cert parse, AESGCM encrypt) are within the stock
  build's run-to-run noise band (±3%) on all five metrics.

## Reproducing

```sh
git clone --branch v0.29.0 https://github.com/PyO3/pyo3.git ../pyo3
git -C ../pyo3 apply $(pwd)/pyo3-codegen-experiment/pyo3-codegen-slim.patch
cat >> Cargo.toml <<'EOF'

[patch.crates-io]
pyo3 = { path = "../pyo3" }
pyo3-build-config = { path = "../pyo3/pyo3-build-config" }
pyo3-ffi = { path = "../pyo3/pyo3-ffi" }
pyo3-macros = { path = "../pyo3/pyo3-macros" }
pyo3-macros-backend = { path = "../pyo3/pyo3-macros-backend" }
EOF

# expansion size
RUSTC_BOOTSTRAP=1 cargo rustc -p cryptography-rust --lib -- -Zunpretty=expanded | wc -l

# leaf rebuild time
cargo build -p cryptography-rust
touch src/rust/src/lib.rs && time cargo build -p cryptography-rust
```
