C bindings
==========

C bindings are bindings to C libraries, using cffi_ whenever possible.

.. _cffi: https://cffi.readthedocs.io

Bindings live in ``cryptography.hazmat.bindings``.

When modifying the bindings you will need to recompile the C extensions to
test the changes. This can be accomplished with ``pip install -e .`` in the
project root. If you do not do this a ``RuntimeError`` will be raised.

Style guide
-----------

Don't name parameters:

.. code-block:: c

    /* Good */
    long f(long);
    /* Bad */
    long f(long x);

...unless they're inside a struct:

.. code-block:: c

    struct my_struct {
        char *name;
        int number;
        ...;
    };

Include ``void`` if the function takes no arguments:

.. code-block:: c

    /* Good */
    long f(void);
    /* Bad */
    long f();

Wrap lines at 80 characters like so:

.. code-block:: c

    /* Pretend this went to 80 characters */
    long f(long, long,
           int *)

Include a space after commas between parameters:

.. code-block:: c

    /* Good */
    long f(int, char *)
    /* Bad */
    long f(int,char *)

Use C-style ``/* */`` comments instead of C++-style ``//``:

.. code-block:: c

    // Bad
    /* Good */

Values set by ``#define`` should be assigned the appropriate type. If you see
this:

.. code-block:: c

    #define SOME_INTEGER_LITERAL 0x0;
    #define SOME_UNSIGNED_INTEGER_LITERAL 0x0001U;
    #define SOME_STRING_LITERAL "hello";

...it should be added to the bindings like so:

.. code-block:: c

    static const int SOME_INTEGER_LITERAL;
    static const unsigned int SOME_UNSIGNED_INTEGER_LITERAL;
    static const char *const SOME_STRING_LITERAL;

Adding constant, types, functions...
------------------------------------

You can create bindings for any name that exists in some version of
the library you're binding against. However, the project also has to
keep supporting older versions of the library. In order to achieve this,
binding modules have a ``CUSTOMIZATIONS`` constant, and there is a
``CONDITIONAL_NAMES`` constants in
``src/cryptography/hazmat/bindings/openssl/_conditional.py``.

Let's say you want to enable quantum transmogrification. The upstream
library implements this as the following API::

    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_LEFT;
    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_RIGHT;
    typedef ... QM_TRANSMOGRIFICATION_CTX;
    int QM_transmogrify(QM_TRANSMOGRIFICATION_CTX *, int);

To start, create a new constant that defines if the *actual* library
has the feature you want, and add it to ``TYPES``::

    static const long Cryptography_HAS_QUANTUM_TRANSMOGRIFICATION;

This should start with ``Cryptography_``, since we're adding it in
this library. This prevents namespace collisions.

Then, define the actual features (constants, types, functions...) you
want to expose. If it's a constant, just add it to ``TYPES``::

    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_LEFT;
    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_RIGHT;

If it's a struct, add it to ``TYPES`` as well. The following is an
opaque struct::

    typedef ... QM_TRANSMOGRIFICATION_CTX;

... but you can also make some or all items in the struct accessible::

    typedef struct {
        /* Fundamental constant k for your particular universe */
        BIGNUM *k;
        ...;
    } QM_TRANSMOGRIFICATION_CTX;

For functions just add the signature to ``FUNCTIONS``::

    int QM_transmogrify(QM_TRANSMOGRIFICATION_CTX *, int);

Then, we define the ``CUSTOMIZATIONS`` entry. To do that, we have to
come up with a C preprocessor expression that decides whether or not a
feature exists in the library. For example::

    #ifdef QM_transmogrify

Then, we set the flag that signifies the feature exists::

    static const long Cryptography_HAS_QUANTUM_TRANSMOGRIFICATION = 1;

Otherwise, we set that flag to 0::

    #else
    static const long Cryptography_HAS_QUANTUM_TRANSMOGRIFICATION = 0;

Then, in that ``#else`` block, we define the names that aren't
available as dummy values. For an integer constant, use 0::

    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_LEFT = 0;
    static const int QM_TRANSMOGRIFICATION_ALIGNMENT_RIGHT = 0;

For a function, it's a bit trickier. You have to define a function
pointer of the appropriate type to be NULL::

    int (*QM_transmogrify)(QM_TRANSMOGRIFICATION_CTX *, int) = NULL;

(To do that, copy the signature, put a ``*`` in front of the function
name and wrap it in parentheses, and then put ``= NULL`` at the end).

Note how types don't need to be conditionally defined, as long as all
the necessarily type definitions are in place.

Finally, add an entry to ``CONDITIONAL_NAMES`` with all of the things
you want to conditionally export::

    def cryptography_has_quantum_transmogrification():
        return [
            "QM_TRANSMOGRIFICATION_ALIGNMENT_LEFT",
            "QM_TRANSMOGRIFICATION_ALIGNMENT_RIGHT",
            "QM_transmogrify",
        ]


    CONDITIONAL_NAMES = {
        ...
        "Cryptography_HAS_QUANTUM_TRANSMOGRIFICATION": (
            cryptography_has_quantum_transmogrification
        ),
    }


Caveats
~~~~~~~

Sometimes, a set of loosely related features are added in the same
version, and it's impractical to create ``#ifdef`` statements for each
one. In that case, it may make sense to either check for a particular
version. For example, to check for OpenSSL 1.1.1 or newer::

    #if CRYPTOGRAPHY_OPENSSL_111_OR_GREATER

Sometimes, the version of a library on a particular platform will have
features that you thought it wouldn't, based on its version.
Occasionally, packagers appear to ship arbitrary VCS checkouts. As a
result, sometimes you may have to add separate ``#ifdef`` statements
for particular features. This kind of issue is typically only caught
by running the tests on a wide variety of systems, which is the job of
our continuous integration infrastructure.
