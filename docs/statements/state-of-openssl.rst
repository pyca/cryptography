===============================================
The State of OpenSSL for ``pyca/cryptography``
===============================================
**Published: January 14, 2026**

For the past 12 years, we (Paul Kehrer and Alex Gaynor) have maintained the Python ``cryptography`` library (also known as ``pyca/cryptography`` or `cryptography.io`_). For that entire period, we've relied on OpenSSL to provide core cryptographic algorithms. This past October, `we gave a talk at the OpenSSL Conference`_ describing our experiences. This talk focuses on the growing problems we have with OpenSSL's direction. The mistakes we see in OpenSSL's development have become so significant that we believe substantial changes are required — either to OpenSSL, or to our reliance on it.

Fundamentally, OpenSSL's trajectory can be understood as a play in three acts:

* In the pre-Heartbleed era (pre-2014), OpenSSL was under-maintained and languishing, substantially lagging behind expectations.
* In the immediate post-Heartbleed era, OpenSSL's maintenance was reinvigorated and it made substantial progress and improvements. It grew a real code review process, began running tests in CI, adopted fuzz testing, and matured its release process.
* Finally, in 2021 OpenSSL 3 was released. OpenSSL 3 introduced new APIs and had large internal refactors. Relative to previous OpenSSL versions, OpenSSL 3 had significant regressions in performance, complexity, API ergonomics, and didn't make needed improvements in areas like testing, verification, and memory safety. Over the same period, OpenSSL's forks have all made progress in these areas. Many of our concerns about OpenSSL's direction in this time have substantial overlap with `those highlighted by HAProxy`_.

The remainder of this post describes the problems we have with OpenSSL in more detail, and concludes with the changes we are making to our own policies in response. To avoid burying the lede, we intend to pursue several approaches to reducing our reliance on OpenSSL.

Performance
===========

Compared to OpenSSL 1.1.1, OpenSSL 3 has significant performance regressions in areas such as parsing and key loading.

Several years ago, we filed a bug reporting that elliptic curve public key loading had regressed 5-8x between OpenSSL 1.1.1 and 3.0.7. The reason we had noticed this is that performance had gotten so bad that we'd seen it in our test suite runtimes. Since then, OpenSSL has improved performance such that it's *only* 3x slower than it used to be. But more significantly, the response to the issue was that, 'regression was expected with OpenSSL 3, and while there might be some optimizations, we shouldn't expect it to ever get back to 1.1.1 levels'. Performance regressions can be acceptable, and even appropriate, when they improve other areas of the library, however as we'll describe, the cause of these regressions has been *other* mistakes, and not offsetting improvements.

As a result of these sorts of regressions, when ``pyca/cryptography`` migrated X.509 certificate parsing from OpenSSL to our own Rust code, we got a 10x performance improvement relative to OpenSSL 3 (n.b., some of this improvement is attributable to advantages in our own code, but much is explainable by the OpenSSL 3 regressions). Later, moving public key parsing to our own Rust code made end-to-end X.509 path validation 60% faster — just improving key loading led to a 60% end-to-end improvement, that's how extreme the overhead of key parsing in OpenSSL was.

The fact that we are able to achieve better performance doing our own parsing makes clear that doing better is practical. And indeed, our performance is not a result of clever SIMD micro-optimizations, it's the result of doing simple things that work: we avoid copies, allocations, hash tables, indirect calls, and locks — none of which should be required for parsing basic DER structures.

Complexity and APIs
===================

OpenSSL 3 started the process of substantially changing its APIs — it introduced ``OSSL_PARAM`` and has been using those for all new API surfaces (including those for post-quantum cryptographic algorithms). In short, ``OSSL_PARAM`` works by passing arrays of key-value pairs to functions, instead of normal argument passing. This reduces performance, reduces compile-time verification, increases verbosity, and makes code less readable. To the extent there is an argument in favor of it, we infer that the benefit is that it allows OpenSSL to use the same API (and ABI) for different algorithms with different parameters, allowing things like reading algorithm parameters from configuration files with generic configuration parsing code that doesn't need to be updated when new algorithms are added to OpenSSL.

For a concrete comparison of the verbosity, performing an ML-KEM encapsulation with OpenSSL takes 37 lines with 6 fallible function calls. Doing so with BoringSSL takes 19 lines with 3 fallible function calls.

In addition to making public APIs more frustrating and error prone to use, OpenSSL internals have also become more complex. For example, in order to make managing arrays of ``OSSL_PARAM`` palatable, many OpenSSL source files are no longer simply C files, they now have a custom Perl preprocessor for their C code.

OpenSSL 3 also introduced the notion of "providers" (obsoleting, but not replacing, the previous ENGINE APIs), which allow for external implementations of algorithms (including algorithms provided by OpenSSL itself). This was the source of innumerable performance regressions, due to poorly designed APIs. In particular, OpenSSL allowed replacing any algorithm at any point in program execution, which necessitated adding innumerable allocations and locks to nearly every operation. To mitigate this, OpenSSL then added more caches, and ultimately RCU (Read-Copy-Update) — a complex memory management strategy which had difficult to diagnose bugs.

From our perspective, this is a cycle of compounding bad decisions: the providers API was incorrectly designed (there is no need to be able to redefine SHA-256 at arbitrary points in program execution) leading to performance regressions. This led to additional complexity to mitigate those regressions in the form of caching and RCU, which in term led to more bugs. And after all that, performance was *still* worse than it had been at the beginning.

Finally, taking an OpenSSL public API and attempting to trace the implementation to see how it is implemented has become an exercise in self-flagellation. Being able to read the source to understand how something works is important both as part of `self-improvement in software engineering`_, but also because as sophisticated consumers there are inevitably things about how an implementation works that aren't documented, and reading the source gives you ground truth. The number of indirect calls, optional paths, ``#ifdef``, and other obstacles to comprehension is astounding. We cannot overstate the extent to which just reading the OpenSSL source code has become miserable — in a way that both wasn't true previously, and isn't true in LibreSSL, BoringSSL, or AWS-LC.


Testing and Verification
=========================

We joke that the Python Cryptographic Authority is a CI engineering project that incidentally produces a cryptography library. The joke reflects our real belief that investment in testing and automation enables `Pareto improvements`_ in development speed and correctness — to the point that it can make other work look trivial.

The OpenSSL project does not sufficiently prioritize testing. While OpenSSL's testing has improved substantially since the pre-Heartbleed era there are quite significant gaps. The gaps in OpenSSL's test coverage were acutely visible during the OpenSSL 3.0 development cycle — where the project was extremely reliant on the community to report regressions experienced during the extended alpha and beta period (covering 19 pre-releases over the course of 16 months), because their own tests were insufficient to catch unintended real-world breakages. Despite the known gaps in OpenSSL's test coverage, it's still common for bug fixes to land without an accompanying regression test.

OpenSSL's CI is exceptionally flaky, and the OpenSSL project has grown to tolerate this flakiness, which masks serious bugs. OpenSSL 3.0.4 contained a critical buffer overflow in the RSA implementation on AVX-512-capable CPUs. This bug was actually caught by CI — but because the crash only occurred when the CI runner happened to have an AVX-512 CPU (not all did), the failures were apparently dismissed as flakiness. Three years later, the project still merges code with failing tests: the day we prepared our conference slides, five of ten recent commits had failing CI checks, and the day before we delivered the talk, every single commit had failing cross-compilation builds.

This incident also speaks to the value of adopting tools like Intel SDE, which allows controlled testing against CPUs with different subsets of x86-64 extension instructions. Using Intel SDE to have dedicated test jobs with and without AVX-512 would have made the nature of the failure immediately legible and reproducible.

OpenSSL is not keeping pace with the state of the art in formal verification. Formal methods have gone from academic novelty to practical reality for meaningful chunks of cryptographic code. BoringSSL and AWS-LC have incorporated formally verified implementations and use automated reasoning to increase assurance.

Memory Safety
=============

At the time OpenSSL was created, there were no programming languages that meaningfully provided performance, embeddability, and memory safety — if you wanted a memory safe language, you were committing to giving up performance and adding a garbage collector.

The world has changed. Nearly 5 years ago, ``pyca/cryptography`` issued our first release incorporating Rust code, and since then we have migrated nearly all functionality to Rust, using a mix of pure-Rust for all parsing and X.509 operations combined with using OpenSSL for providing cryptographic algorithms — gaining performance wins and avoiding several OpenSSL CVEs. `We know these transitions are possible`_.

A library committed to security needs to make a long-term commitment to a migration to a memory safe programming language. OpenSSL has shown no initiative at all on this issue.

Contributing Causes
===================

Whenever issues with an open source project are raised, many will suggest this is an issue of funding or tragedy of the commons. This is inapposite, in the past decade, post-Heartbleed, OpenSSL has received considerable funding, and at this moment the OpenSSL Corporation and Foundation employ more software engineers than work full time on either BoringSSL or LibreSSL. The problems we have described are not ones caused by underfunding.

We do not fully understand the motivations that led to the public APIs and internal complexity we've described here. We've done our best to reverse engineer them by asking "what would motivate someone to do this" and often we've found ourselves coming up short. The fact that none of the other OpenSSL forks have made these same design choices is informative to the question of "was this necessary".

Future Directions
=================

Our experience with OpenSSL has been on a negative trajectory for several years. As a result of these issues, we are making the following changes to our (admittedly undocumented) policies.

First, we will no longer require OpenSSL implementations for new functionality. Where we deem it desirable, we will add new APIs that are only on LibreSSL/BoringSSL/AWS-LC. Concretely, we expect to add ML-KEM and ML-DSA APIs that are only available with LibreSSL/BoringSSL/AWS-LC, and not with OpenSSL.

Second, we currently statically link a copy of OpenSSL in our wheels (binary artifacts). We are beginning the process of looking into what would be required to change our wheels to link against one of the OpenSSL forks.

If we are able to successfully switch to one of OpenSSL's forks for our binary wheels, we will begin considering the circumstances under which we would drop support for OpenSSL entirely.

Lastly, in the long term, we are actively tracking non-OpenSSL derived cryptography libraries such as Graviola as potential alternatives.

We recognize that changes in which libraries we use to provide cryptographic implementations have substantial impact on our users — particularly redistributors. We do not contemplate these steps lightly, nor do we anticipate making them hastily. However, due to the gravity of our concerns, we are compelled to act. If you rely on ``pyca/cryptography``'s support for OpenSSL, the best way to avoid the most drastic steps contemplated here is to engage with the OpenSSL project and contribute to improvements on these axes.

.. _`cryptography.io`: http://cryptography.io
.. _`we gave a talk at the OpenSSL Conference`: https://www.youtube.com/watch?v=RUIguklWwx0
.. _`those highlighted by HAProxy`: https://www.haproxy.com/blog/state-of-ssl-stacks
.. _`Pareto improvements`: https://en.wikipedia.org/wiki/Pareto_efficiency
.. _`self-improvement in software engineering`: https://alexgaynor.net/2019/jul/11/read-code-more/
.. _`We know these transitions are possible`: https://www.youtube.com/watch?v=z_Eiy2W0APU
