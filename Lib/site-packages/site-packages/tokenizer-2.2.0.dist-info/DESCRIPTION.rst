-----------------------------------------
Tokenizer: A tokenizer for Icelandic text
-----------------------------------------

.. image:: https://travis-ci.com/mideind/Tokenizer.svg?branch=master
   :target: https://travis-ci.com/mideind/Tokenizer


Overview
--------

Tokenization is a necessary first step in many natural language processing
tasks, such as word counting, parsing, spell checking, corpus generation, and
statistical analysis of text.

**Tokenizer** is a compact pure-Python (2 and 3) executable program and module
for tokenizing Icelandic text. It converts input text to streams of *tokens*,
where each token is a separate word, punctuation sign, number/amount, date,
e-mail, URL/URI, etc. It also segments the token stream into sentences,
considering corner cases such as abbreviations and dates in the middle
of sentences.

The package contains a dictionary of common Icelandic abbreviations,
in the file ``src/tokenizer/Abbrev.conf``.

Tokenizer is an independent spinoff from the `Greynir project <https://greynir.is>`_
(GitHub repository `here <https://github.com/mideind/Greynir>`_), by the same authors.
The `Greynir natural language parser for Icelandic <https://github.com/mideind/ReynirPackage>`_
uses Tokenizer on its input.

Note that Tokenizer is licensed under the *MIT* license
while Greynir is licensed under *GPLv3*.


Deep vs. shallow tokenization
-----------------------------

Tokenizer can do both *deep* and *shallow* tokenization.

*Shallow* tokenization simply returns each sentence as a string (or as a line
of text in an output file), where the individual tokens are separated
by spaces.

*Deep* tokenization returns token objects that have been annotated with
the token type and further information extracted from the token, for example
a *(year, month, day)* tuple in the case of date tokens.

In shallow tokenization, tokens are in most cases kept intact, although
consecutive white space is always coalesced. The input strings
``"800 MW"``, ``"21. janúar"`` and ``"800 7000"`` thus become
two tokens each, output with a single space between them.

In deep tokenization, the same strings are represented by single token objects,
of type ``TOK.MEASUREMENT``, ``TOK.DATEREL`` and ``TOK.TELNO``, respectively.
The text associated with a single token object may contain one or more spaces,
although consecutive space is always coalesced.

By default, the command line tool performs shallow tokenization. If you
want deep tokenization with the command line tool, use the ``--json`` or
``--csv`` switches.

>From Python code, call ``split_into_sentences()`` for shallow tokenization,
or ``tokenize()`` for deep tokenization. These functions are documented with
examples below.


Installation
------------

To install:

.. code-block:: console

    $ pip install tokenizer


Command line tool
-----------------

After installation, the tokenizer can be invoked directly from
the command line:

.. code-block:: console

    $ tokenize input.txt output.txt

Input and output files are encoded in UTF-8. If the files are not
given explicitly, ``stdin`` and ``stdout`` are used for input and output,
respectively.

Empty lines in the input are treated as sentence boundaries.

By default, the output consists of one sentence per line, where each
line ends with a single newline character (ASCII LF, ``chr(10)``, ``"\n"``).
Within each line, tokens are separated by spaces.

The following (mutually exclusive) options can be specified
on the command line:

+-------------------+---------------------------------------------------+
| | ``--csv``       | Deep tokenization. Output token objects in CSV    |
|                   | format, one per line. Sentences are separated by  |
|                   | lines containing ``0,"",""``                      |
+-------------------+---------------------------------------------------+
| | ``--json``      | Deep tokenization. Output token objects in JSON   |
|                   | format, one per line.                             |
+-------------------+---------------------------------------------------+
| | ``--normalize`` | Normalize punctuation, causing e.g. quotes to be  |
|                   | output in Icelandic form and hyphens to be        |
|                   | regularized. This option is only applicable to    |
|                   | shallow tokenization.                             |
+-------------------+---------------------------------------------------+

Type ``tokenize -h`` or ``tokenize --help`` to get a short help message.

Example
=======

.. code-block:: console

    $ echo "3.janúar sl. keypti   ég 64kWst rafbíl. Hann kostaði € 30.000." | tokenize
    3. janúar sl. keypti ég 64kWst rafbíl .
    Hann kostaði €30.000 .

    $ echo "3.janúar sl. keypti   ég 64kWst rafbíl. Hann kostaði € 30.000." | tokenize --csv
    19,"3. janúar","0|1|3"
    6,"sl.","síðastliðinn"
    6,"keypti",""
    6,"ég",""
    22,"64kWst","J|230400000.0"
    6,"rafbíl",""
    1,".","."
    0,"",""
    6,"Hann",""
    6,"kostaði",""
    13,"€30.000","30000|EUR"
    1,".","."
    0,"",""

    $ echo "3.janúar sl. keypti   ég 64kWst rafbíl. Hann kostaði € 30.000." | tokenize --json
    {"k":"BEGIN SENT"}
    {"k":"DATEREL","t":"3. janúar","v":[0,1,3]}
    {"k":"WORD","t":"sl.","v":["síðastliðinn"]}
    {"k":"WORD","t":"keypti"}
    {"k":"WORD","t":"ég"}
    {"k":"MEASUREMENT","t":"64kWst","v":["J",230400000.0]}
    {"k":"WORD","t":"rafbíl"}
    {"k":"PUNCTUATION","t":".","v":"."}
    {"k":"END SENT"}
    {"k":"BEGIN SENT"}
    {"k":"WORD","t":"Hann"}
    {"k":"WORD","t":"kostaði"}
    {"k":"AMOUNT","t":"€30.000","v":[30000,"EUR"]}
    {"k":"PUNCTUATION","t":".","v":"."}
    {"k":"END SENT"}

Python module
-------------

Shallow tokenization example
============================

An example of shallow tokenization from Python code goes something like this:

.. code-block:: python

    from __future__ import print_function
    # The following import is optional but convenient under Python 2.7
    from __future__ import unicode_literals

    from tokenizer import split_into_sentences

    # A string to be tokenized, containing two sentences
    s = "3.janúar sl. keypti   ég 64kWst rafbíl. Hann kostaði € 30.000."

    # Obtain a generator of sentence strings
    g = split_into_sentences(s)

    # Loop through the sentences
    for sentence in g:

        # Obtain the individual token strings
        tokens = sentence.split()

        # Print the tokens, comma-separated
        print(", ".join(tokens))

The program outputs::

    3., janúar, sl., keypti, ég, 64kWst, rafbíl, .
    Hann, kostaði, €30.000, .

Deep tokenization example
=========================

To do deep tokenization from within Python code:

.. code-block:: python

    # The following import is optional but convenient under Python 2.7
    from __future__ import unicode_literals
    from tokenizer import tokenize, TOK

    text = ("Málinu var vísað til stjórnskipunar- og eftirlitsnefndar "
        "skv. 3. gr. XVII. kafla laga nr. 10/2007 þann 3. janúar 2010.")

    for token in tokenize(text):

        print("{0}: '{1}' {2}".format(
            TOK.descr[token.kind],
            token.txt or "-",
            token.val or ""))

Output::

    BEGIN SENT: '-' (0, None)
    WORD: 'Málinu'
    WORD: 'var'
    WORD: 'vísað'
    WORD: 'til'
    WORD: 'stjórnskipunar- og eftirlitsnefndar'
    WORD: 'skv.' [('samkvæmt', 0, 'fs', 'skst', 'skv.', '-')]
    ORDINAL: '3.' 3
    WORD: 'gr.' [('grein', 0, 'kvk', 'skst', 'gr.', '-')]
    ORDINAL: 'XVII.' 17
    WORD: 'kafla'
    WORD: 'laga'
    WORD: 'nr.' [('númer', 0, 'hk', 'skst', 'nr.', '-')]
    NUMBER: '10' (10, None, None)
    PUNCTUATION: '/' (4, '/')
    YEAR: '2007' 2007
    WORD: 'þann'
    DATEABS: '3. janúar 2010' (2010, 1, 3)
    PUNCTUATION: '.' (3, '.')
    END SENT: '-'

Note the following:

- Sentences are delimited by ``TOK.S_BEGIN`` and ``TOK.S_END`` tokens.
- Composite words, such as *stjórnskipunar- og eftirlitsnefndar*,
  are coalesced into one token.
- Well-known abbreviations are recognized and their full expansion
  is available in the ``token.val`` field.
- Ordinal numbers (*3., XVII.*) are recognized and their value (*3, 17*)
  is available in the ``token.val``  field.
- Dates, years and times, both absolute and relative, are recognized and
  the respective year, month, day, hour, minute and second
  values are included as a tuple in ``token.val``.
- Numbers, both integer and real, are recognized and their value
  is available in the ``token.val`` field.
- Further details of how Tokenizer processes text can be inferred from the
  `test module <https://github.com/mideind/Tokenizer/blob/master/test/test_tokenizer.py>`_
  in the project's `GitHub repository <https://github.com/mideind/Tokenizer>`_.


The ``tokenize()`` function
---------------------------

To deep-tokenize a text string, call ``tokenizer.tokenize(text, **options)``.
The ``text`` parameter can be a string, or an iterable that yields strings
(such as a text file object).

The function returns a Python *generator* of token objects.
Each token object is a simple ``namedtuple`` with three
fields: ``(kind, txt, val)`` (further documented below).

The ``tokenizer.tokenize()`` function is typically called in a ``for`` loop:

.. code-block:: python

    import tokenizer
    for token in tokenizer.tokenize(mystring):
        kind, txt, val = token
        if kind == tokenizer.TOK.WORD:
            # Do something with word tokens
            pass
        else:
            # Do something else
            pass

Alternatively, create a token list from the returned generator::

    token_list = list(tokenizer.tokenize(mystring))

In Python 2.7, you can pass either ``unicode`` strings or ``str``
byte strings to ``tokenizer.tokenize()``. In the latter case, the
byte string is assumed to be encoded in UTF-8.


The ``split_into_sentences()`` function
---------------------------------------

To shallow-tokenize a text string, call
``tokenizer.split_into_sentences(text_or_gen, **options)``.
The ``text_or_gen`` parameter can be a string, or an iterable that yields
strings (such as a text file object).

This function returns a Python *generator* of strings, yielding a string
for each sentence in the input. Within a sentence, the tokens are
separated by spaces.

You can pass the option ``normalize=True`` to the function if you want
the normalized form of punctuation tokens. Normalization outputs
Icelandic single and double quotes („these“) instead of English-style
ones ("these"), converts three-dot ellipsis ... to single character
ellipsis …, and casts en-dashes – and em-dashes — to regular hyphens.

The ``tokenizer.split_into_sentences()`` function is typically called
in a ``for`` loop:

.. code-block:: python

    import tokenizer
    with open("example.txt", "r", encoding="utf-8") as f:
        # You can pass a file object directly to split_into_sentences()
        for sentence in tokenizer.split_into_sentences(f):
            # sentence is a string of space-separated tokens
            tokens = sentence.split()
            # Now, tokens is a list of strings, one for each token
            for t in tokens:
                # Do something with the token t
                pass


The ``correct_spaces()`` function
---------------------------------

The ``tokenizer.correct_spaces(text)`` function returns a string after
splitting it up and re-joining it with correct whitespace around
punctuation tokens. Example::

    >>> import tokenizer
    >>> tokenizer.correct_spaces(
    ... "Frétt \n  dagsins:Jón\t ,Friðgeir og Páll ! 100  /  2  =   50"
    ... )
    'Frétt dagsins: Jón, Friðgeir og Páll! 100/2 = 50'


The ``detokenize()`` function
---------------------------------

The ``tokenizer.detokenize(tokens, normalize=False)`` function
takes an iterable of token objects and returns a corresponding, correctly
spaced text string, composed from the tokens' text. If the
``normalize`` parameter is set to ``True``,
the function uses the normalized form of any punctuation tokens, such
as proper Icelandic single and double quotes instead of English-type
quotes. Example::

    >>> import tokenizer
    >>> toklist = list(tokenizer.tokenize("Hann sagði: „Þú ert ágæt!“."))
    >>> tokenizer.detokenize(toklist, normalize=True)
    'Hann sagði: „Þú ert ágæt!“.'


The ``normalized_text()`` function
----------------------------------

The ``tokenizer.normalized_text(token)`` function
returns the normalized text for a token. This means that the original
token text is returned except for certain punctuation tokens, where a
normalized form is returned instead. Specifically, English-type quotes
are converted to Icelandic ones, and en- and em-dashes are converted
to regular hyphens.


The ``text_from_tokens()`` function
-----------------------------------

The ``tokenizer.text_from_tokens(tokens)`` function
returns a concatenation of the text contents of the given token list,
with spaces between tokens. Example::

    >>> import tokenizer
    >>> toklist = list(tokenizer.tokenize("Hann sagði: \"Þú ert ágæt!\"."))
    >>> tokenizer.text_from_tokens(toklist)
    'Hann sagði : " Þú ert ágæt ! " .'


The ``normalized_text_from_tokens()`` function
----------------------------------------------

The ``tokenizer.normalized_text_from_tokens(tokens)`` function
returns a concatenation of the normalized text contents of the given
token list, with spaces between tokens. Example (note the double quotes)::

    >>> import tokenizer
    >>> toklist = list(tokenizer.tokenize("Hann sagði: \"Þú ert ágæt!\"."))
    >>> tokenizer.normalized_text_from_tokens(toklist)
    'Hann sagði : „ Þú ert ágæt ! “ .'


Tokenization options
--------------------

You can optionally pass one or more of the following options as
keyword parameters to the ``tokenize()`` and ``split_into_sentences()``
functions:


* ``convert_numbers=[bool]``

  Setting this option to ``True`` causes the tokenizer to convert numbers
  and amounts with
  English-style decimal points (``.``) and thousands separators (``,``)
  to Icelandic format, where the decimal separator is a comma (``,``)
  and the thousands separator is a period (``.``). ``$1,234.56`` is thus
  converted to a token whose text is ``$1.234,56``.

  The default value for the ``convert_numbers`` option is ``False``.

  Note that in versions of Tokenizer prior to 1.4, ``convert_numbers``
  was ``True``.


* ``convert_measurements=[bool]``

  Setting this option to ``True`` causes the tokenizer to convert
  degrees Kelvin, Celsius and Fahrenheit to a regularized form, i.e.
  ``200° C`` becomes ``200 °C``.

  The default value for the ``convert_measurements`` option is ``False``.


* ``handle_kludgy_ordinals=[value]``

  This options controls the way Tokenizer handles 'kludgy' ordinals, such as
  *1sti*, *4ðu*, or *2ja*. By default, such ordinals are returned unmodified
  ('passed through') as word tokens (``TOK.WORD``).
  However, this can be modified as follows:

  * ``tokenizer.KLUDGY_ORDINALS_MODIFY``: Kludgy ordinals are corrected
    to become 'proper' word tokens, i.e. *1sti* becomes *fyrsti* and
    *2ja* becomes *tveggja*.

  * ``tokenizer.KLUDGY_ORDINALS_TRANSLATE``: Kludgy ordinals that represent
    proper ordinal numbers are translated to ordinal tokens (``TOK.ORDINAL``),
    with their original text and their ordinal value. *1sti* thus
    becomes a ``TOK.ORDINAL`` token with a value of 1, and *3ja* becomes
    a ``TOK.ORDINAL`` with a value of 3.

  * ``tokenizer.KLUDGY_ORDINALS_PASS_THROUGH`` is the default value of
    the option. It causes kludgy ordinals to be returned unmodified as
    word tokens.

  Note that versions of Tokenizer prior to 1.4 behaved as if
  ``handle_kludgy_ordinals`` were set to
  ``tokenizer.KLUDGY_ORDINALS_TRANSLATE``.


The token object
----------------

Each token is represented by a ``namedtuple`` with three fields:
``(kind, txt, val)``.


The ``kind`` field
==================

The ``kind`` field contains one of the following integer constants,
defined within the ``TOK`` class:

+---------------+---------+---------------------+---------------------------+
| Constant      |  Value  | Explanation         | Examples                  |
+===============+=========+=====================+===========================+
| PUNCTUATION   |    1    | Punctuation         | . ! ; % &                 |
+---------------+---------+---------------------+---------------------------+
| TIME          |    2    | Time (h, m, s)      | | 11:35:40                |
|               |         |                     | | kl. 7:05                |
|               |         |                     | | klukkan 23:35           |
+---------------+---------+---------------------+---------------------------+
| DATE *        |    3    | Date (y, m, d)      | [Unused, see DATEABS and  |
|               |         |                     | DATEREL]                  |
+---------------+---------+---------------------+---------------------------+
| YEAR          |    4    | Year                | | árið 874 e.Kr.          |
|               |         |                     | | 1965                    |
|               |         |                     | | 44 f.Kr.                |
+---------------+---------+---------------------+---------------------------+
| NUMBER        |    5    | Number              | | 100                     |
|               |         |                     | | 1.965                   |
|               |         |                     | | 1.965,34                |
|               |         |                     | | 1,965.34                |
|               |         |                     | | 2⅞                      |
+---------------+---------+---------------------+---------------------------+
| WORD          |    6    | Word                | | kattaeftirlit           |
|               |         |                     | | hunda- og kattaeftirlit |
+---------------+---------+---------------------+---------------------------+
| TELNO         |    7    | Telephone number    | | 5254764                 |
|               |         |                     | | 699-4244                |
|               |         |                     | | 410 4000                |
+---------------+---------+---------------------+---------------------------+
| PERCENT       |    8    | Percentage          | 78%                       |
+---------------+---------+---------------------+---------------------------+
| URL           |    9    | URL                 | | https://greynir.is      |
|               |         |                     | | http://tiny.cc/28695y   |
+---------------+---------+---------------------+---------------------------+
| ORDINAL       |    10   | Ordinal number      | | 30.                     |
|               |         |                     | | XVIII.                  |
+---------------+---------+---------------------+---------------------------+
| TIMESTAMP *   |    11   | Timestamp           | [Unused, see              |
|               |         |                     | TIMESTAMPABS and          |
|               |         |                     | TIMESTAMPREL]             |
+---------------+---------+---------------------+---------------------------+
| CURRENCY *    |    12   | Currency name       | [Unused]                  |
+---------------+---------+---------------------+---------------------------+
| AMOUNT        |    13   | Amount              | | €2.345,67               |
|               |         |                     | | 750 þús.kr.             |
|               |         |                     | | 2,7 mrð. USD            |
|               |         |                     | | kr. 9.900               |
|               |         |                     | | EUR 200                 |
+---------------+---------+---------------------+---------------------------+
| PERSON *      |    14   | Person name         | [Unused]                  |
+---------------+---------+---------------------+---------------------------+
| EMAIL         |    15   | E-mail              | ``fake@news.is``          |
+---------------+---------+---------------------+---------------------------+
| ENTITY *      |    16   | Named entity        | [Unused]                  |
+---------------+---------+---------------------+---------------------------+
| UNKNOWN       |    17   | Unknown token       |                           |
+---------------+---------+---------------------+---------------------------+
| DATEABS       |    18   | Absolute date       | | 30. desember 1965       |
|               |         |                     | | 30/12/1965              |
|               |         |                     | | 1965-12-30              |
|               |         |                     | | 1965/12/30              |
+---------------+---------+---------------------+---------------------------+
| DATEREL       |    19   | Relative date       | | 15. mars                |
|               |         |                     | | 15/3                    |
|               |         |                     | | 15.3.                   |
|               |         |                     | | mars 1911               |
+---------------+---------+---------------------+---------------------------+
| TIMESTAMPABS  |    20   | Absolute timestamp  | | 30. desember 1965 11:34 |
|               |         |                     | | 1965-12-30 kl. 13:00    |
+---------------+---------+---------------------+---------------------------+
| TIMESTAMPREL  |    21   | Relative timestamp  | | 30. desember kl. 13:00  |
+---------------+---------+---------------------+---------------------------+
| MEASUREMENT   |    22   | Value with a        | | 690 MW                  |
|               |         | measurement unit    | | 1.010 hPa               |
|               |         |                     | | 220 m²                  |
|               |         |                     | | 80° C                   |
+---------------+---------+---------------------+---------------------------+
| NUMWLETTER    |    23   | Number followed by  | | 14a                     |
|               |         | a single letter     | | 7B                      |
+---------------+---------+---------------------+---------------------------+
| DOMAIN        |    24   | Domain name         | | greynir.is              |
|               |         |                     | | Reddit.com              |
|               |         |                     | | www.wikipedia.org       |
+---------------+---------+---------------------+---------------------------+
| HASHTAG       |    25   | Hashtag             | | #MeToo                  |
|               |         |                     | | #12stig                 |
+---------------+---------+---------------------+---------------------------+
| MOLECULE      |    26   | Molecular formula   | | H2SO4                   |
|               |         |                     | | CO2                     |
+---------------+---------+---------------------+---------------------------+
| SSN           |    27   | Social security     | | 591213-1480             |
|               |         | number (*kennitala*)|                           |
+---------------+---------+---------------------+---------------------------+
| USERNAME      |    28   | Twitter user handle | | @username_123           |
|               |         |                     |                           |
+---------------+---------+---------------------+---------------------------+
| SERIALNUMBER  |    29   | Serial number       | | 394-5388                |
|               |         |                     | | 12-345-6789             |
+---------------+---------+---------------------+---------------------------+
| COMPANY *     |    30   | Company name        | [Unused]                  |
+---------------+---------+---------------------+---------------------------+
| S_BEGIN       |  11001  | Start of sentence   |                           |
+---------------+---------+---------------------+---------------------------+
| S_END         |  11002  | End of sentence     |                           |
+---------------+---------+---------------------+---------------------------+

(*) The token types marked with an asterisk are reserved for the Greynir package
and not currently returned by the tokenizer.

To obtain a descriptive text for a token kind, use
``TOK.descr[token.kind]`` (see example above).


The ``txt`` field
==================

The ``txt`` field contains the original source text for the token,
with the following exceptions:

* All contiguous whitespace (spaces, tabs, newlines) is coalesced
  into single spaces (``" "``) within the ``txt`` field. A date
  token that is parsed from a source text of ``"29.  \n   janúar"``
  thus has a ``txt`` of ``"29. janúar"``.

* Tokenizer automatically merges Unicode ``COMBINING ACUTE ACCENT``
  (code point 769) and ``COMBINING DIAERESIS`` (code point 776)
  with vowels to form single code points for the Icelandic letters
  á, é, í, ó, ú, ý and ö, in both lower and upper case.

* If the appropriate options are specified (see above), it converts
  kludgy ordinals (*3ja*) to proper ones (*þriðja*), and English-style
  thousand and decimal separators to Icelandic ones
  (*10,345.67* becomes *10.345,67*).


The ``val`` field
==================

The ``val`` field contains auxiliary information, corresponding to
the token kind, as follows:

- For ``TOK.PUNCTUATION``, the ``val`` field contains a tuple with
  two items: ``(whitespace, normalform)``. The first item (``token.val[0]``)
  specifies the whitespace normally found around the symbol in question,
  as an integer::

    TP_LEFT = 1   # Whitespace to the left
    TP_CENTER = 2 # Whitespace to the left and right
    TP_RIGHT = 3  # Whitespace to the right
    TP_NONE = 4   # No whitespace

  The second item (``token.val[1]``) contains a normalized representation of the
  punctuation. For instance, various forms of single and double
  quotes are represented as Icelandic ones (i.e. „these“ or ‚these‘) in
  normalized form, and ellipsis ("...") are represented as the single
  character "…".
- For ``TOK.TIME``, the ``val`` field contains an
  ``(hour, minute, second)`` tuple.
- For ``TOK.DATEABS``, the ``val`` field contains a
  ``(year, month, day)`` tuple (all 1-based).
- For ``TOK.DATEREL``, the ``val`` field contains a
  ``(year, month, day)`` tuple (all 1-based),
  except that a least one of the tuple fields is missing and set to 0.
  Example: *3. júní* becomes ``TOK.DATEREL`` with the fields ``(0, 6, 3)``
  as the year is missing.
- For ``TOK.YEAR``, the ``val`` field contains the year as an integer.
  A negative number indicates that the year is BCE (*fyrir Krist*),
  specified with the suffix *f.Kr.* (e.g. *árið 33 f.Kr.*).
- For ``TOK.NUMBER``, the ``val`` field contains a tuple
  ``(number, None, None)``.
  (The two empty fields are included for compatibility with Greynir.)
- For ``TOK.WORD``, the ``val`` field contains the full expansion
  of an abbreviation, as a list containing a single tuple, or ``None``
  if the word is not abbreviated.
- For ``TOK.PERCENT``, the ``val`` field contains a tuple
  of ``(percentage, None, None)``.
- For ``TOK.ORDINAL``, the ``val`` field contains the ordinal value
  as an integer. The original ordinal may be a decimal number
  or a Roman numeral.
- For ``TOK.TIMESTAMP``, the ``val`` field contains
  a ``(year, month, day, hour, minute, second)`` tuple.
- For ``TOK.AMOUNT``, the ``val`` field contains
  an ``(amount, currency, None, None)`` tuple. The amount is a float, and
  the currency is an ISO currency code, e.g. *USD* for dollars ($ sign),
  *EUR* for euros (€ sign) or *ISK* for Icelandic króna
  (*kr.* abbreviation). (The two empty fields are included for
  compatibility with Greynir.)
- For ``TOK.MEASUREMENT``, the ``val`` field contains a ``(unit, value)``
  tuple, where ``unit`` is a base SI unit (such as ``g``, ``m``,
  ``m²``, ``s``, ``W``, ``Hz``, ``K`` for temperature in Kelvin).
- For ``TOK.TELNO``, the ``val`` field contains a tuple: ``(number, cc)``
  where the first item is the phone number
  in a normalized ``NNN-NNNN`` format, i.e. always including a hyphen,
  and the second item is the country code, eventually prefixed by ``+``.
  The country code defaults to ``354`` (Iceland).


Abbreviations
-------------

Abbreviations recognized by Tokenizer are defined in the ``Abbrev.conf``
file, found in the ``src/tokenizer/`` directory. This is a text file with
abbreviations, their definitions and explanatory comments.

When an abbreviation is encountered, it is recognized as a word token
(i.e. having its ``kind`` field equal to ``TOK.WORD``).
Its expansion(s) are included in the token's
``val`` field as a list containing tuples of the format
``(ordmynd, utg, ordfl, fl, stofn, beyging)``.
An example is *o.s.frv.*, which results in a ``val`` field equal to
``[('og svo framvegis', 0, 'ao', 'frasi', 'o.s.frv.', '-')]``.

The tuple format is designed to be compatible with the
*Database of Modern Icelandic Inflection* (*DMII*),
*Beygingarlýsing íslensks nútímamáls*.


Development installation
------------------------

To install Tokenizer in development mode, where you can easily
modify the source files (assuming you have ``git`` available):

.. code-block:: console

    $ git clone https://github.com/mideind/Tokenizer
    $ cd Tokenizer
    $ # [ Activate your virtualenv here, if you have one ]
    $ pip install -e .


Test suite
----------

Tokenizer comes with a large test suite.
The file ``test/test_tokenizer.py`` contains built-in tests that
run under ``pytest``.

To run the built-in tests, install `pytest <https://docs.pytest.org/en/latest/>`_,
``cd`` to your ``Tokenizer`` subdirectory (and optionally
activate your virtualenv), then run:

.. code-block:: console

    $ python -m pytest

The file ``test/toktest_large.txt`` contains a test set of 13,075 lines.
The lines test sentence detection, token detection and token classification.
For analysis, ``test/toktest_large_gold_perfect.txt`` contains
the expected output of a perfect shallow tokenization, and
``test/toktest_large_gold_acceptable.txt`` contains the current output of the
shallow tokenization.

The file ``test/Overview.txt`` (only in Icelandic) contains a description
of the test set, including line numbers for each part in both
``test/toktest_large.txt`` and ``test/toktest_large_gold_acceptable.txt``,
and a tag describing what is being tested in each part.

It also contains a description of a perfect shallow tokenization for each part,
acceptable tokenization and the current behaviour.
As such, the description is an analysis of which edge cases the tokenizer
can handle and which it can not.

To test the tokenizer on the large test set the following needs to be typed
in the command line:

.. code-block:: console

    $ tokenize test/toktest_large.txt test/toktest_large_out.txt

To compare it to the acceptable behaviour:

.. code-block:: console

    $ diff test/toktest_large_out.txt test/toktest_large_gold_acceptable.txt > diff.txt

The file ``test/toktest_normal.txt`` contains a running text from recent
news articles, containing no edge cases. The gold standard for that file
can be found in the file ``test/toktest_normal_gold_expected.txt``.


Changelog
---------

* Version 2.2.0: Fixed ``correct_spaces()`` to handle compounds such as
  *Atvinnu-, nýsköpunar- og ferðamálaráðuneytið* and
  *bensínstöðvar, -dælur og -tankar*.
* Version 2.1.0: Changed handling of periods at end of sentences if they are
  a part of an abbreviation. Now, the period is kept attached to the abbreviation,
  not split off into a separate period token, as before.
* Version 2.0.7: Added ``TOK.COMPANY`` token type; fixed a few abbreviations;
  renamed parameter ``text`` to ``text_or_gen`` in functions that accept a string
  or a string iterator
* Version 2.0.6: Fixed handling of abbreviations such as *m.v.* (*miðað við*)
  that should not start a new sentence even if the following word is capitalized
* Version 2.0.5: Fixed bug where single uppercase letters were erroneously
  being recognized as abbreviations, causing prepositions such as 'Í' and 'Á'
  at the beginning of sentences to be misunderstood in ReynirPackage
* Version 2.0.4: Added imperfect abbreviations (*amk.*, *osfrv.*); recognized
  *klukkan hálf tvö* as a ``TOK.TIME``
* Version 2.0.3: Fixed bug in ``detokenize()`` where abbreviations, domains
  and e-mails containing periods were wrongly split
* Version 2.0.2: Spelled-out day ordinals are no longer included as a part of
  ``TOK.DATEREL`` tokens. Thus, *þriðji júní* is now a ``TOK.WORD``
  followed by a ``TOK.DATEREL``. *3. júní* continues to be parsed as
  a single ``TOK.DATEREL``
* Version 2.0.1: Order of abbreviation meanings within the ``token.val`` field
  made deterministic; fixed bug in measurement unit handling
* Version 2.0.0: Added command line tool; added ``split_into_sentences()``
  and ``detokenize()`` functions; removed ``convert_telno`` option;
  splitting of coalesced tokens made more robust;
  added ``TOK.SSN``, ``TOK.MOLECULE``, ``TOK.USERNAME`` and
  ``TOK.SERIALNUMBER`` token kinds; abbreviations can now have multiple
  meanings
* Version 1.4.0: Added the ``**options`` parameter to the
  ``tokenize()`` function, giving control over the handling of numbers,
  telephone numbers, and 'kludgy' ordinals
* Version 1.3.0: Added ``TOK.DOMAIN`` and ``TOK.HASHTAG`` token types;
  improved handling of capitalized month name *Ágúst*, which is
  now recognized when following an ordinal number; improved recognition
  of telephone numbers; added abbreviations
* Version 1.2.3: Added abbreviations; updated GitHub URLs
* Version 1.2.2: Added support for composites with more than two parts, i.e.
  *„dómsmála-, ferðamála-, iðnaðar- og nýsköpunarráðherra“*; added support for
  ``±`` sign; added several abbreviations
* Version 1.2.1: Fixed bug where the name *Ágúst* was recognized
  as a month name; Unicode nonbreaking and invisible space characters
  are now removed before tokenization
* Version 1.2.0: Added support for Unicode fraction characters;
  enhanced handing of degrees (°, °C, °F); fixed bug in cubic meter
  measurement unit; more abbreviations
* Version 1.1.2: Fixed bug in liter (``l`` and ``ltr``) measurement units
* Version 1.1.1: Added ``mark_paragraphs()`` function
* Version 1.1.0: All abbreviations in ``Abbrev.conf`` are now
  returned with their meaning in a tuple in ``token.val``;
  handling of 'mbl.is' fixed
* Version 1.0.9: Added abbreviation 'MAST'; harmonized copyright headers
* Version 1.0.8: Bug fixes in ``DATEREL``, ``MEASUREMENT`` and ``NUMWLETTER``
  token handling; added 'kWst' and 'MWst' measurement units; blackened
* Version 1.0.7: Added ``TOK.NUMWLETTER`` token type
* Version 1.0.6: Automatic merging of Unicode ``COMBINING ACUTE ACCENT`` and
  ``COMBINING DIAERESIS`` code points with vowels
* Version 1.0.5: Date/time and amount tokens coalesced to a further extent
* Version 1.0.4: Added ``TOK.DATEABS``, ``TOK.TIMESTAMPABS``,
  ``TOK.MEASUREMENT``




