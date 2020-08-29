"""
https://stackoverflow.com/questions/36013295/find-best-substring-match
"""
from difflib import SequenceMatcher
from .utils import round_decimal


def find_best_string(query,
                     corpus,
                     step=4,
                     flex=3,
                     case_sensitive=False):
    """Return best matching substring of corpus.

    Parameters
    ----------
    query : str
    corpus : str
    step : int
        Step size of first match-value scan through corpus. Can be thought of
        as a sort of "scan resolution". Should not exceed length of query.
    flex : int
        Max. left/right substring position adjustment value. Should not
        exceed length of query / 2.

    Outputs
    -------
    output0 : str
        Best matching substring.
    output1 : float
        Match ratio of best matching substring. 1 is perfect match.

    """

    def ratio(a, b):
        """Compact alias for SequenceMatcher."""
        return SequenceMatcher(None, a, b).ratio()

    def scan_corpus(step):
        """Return list of match values from corpus-wide scan."""
        match_values = []
        m = 0
        while m + qlen - step <= len(corpus):
            match_values.append(ratio(query, corpus[m : m-1+qlen]))
            m += step
        return match_values

    def index_max(v):
        """Return index of max value."""
        return max(range(len(v)), key=v.__getitem__)

    def adjust_left_right_positions():
        """Return left/right positions for best string match."""
        # bp_* is synonym for 'Best Position Left/Right' and are adjusted
        # to optimize bmv_*
        p_l, bp_l = [pos] * 2
        p_r, bp_r = [pos + qlen] * 2

        # bmv_* are declared here in case they are untouched in optimization
        bmv_l = match_values[round_decimal(p_l / step)]
        bmv_r = match_values[round_decimal(p_r / step)]

        for f in range(flex):
            ll = ratio(query, corpus[p_l - f: p_r])
            if ll > bmv_l:
                bmv_l = ll
                bp_l = p_l - f

            lr = ratio(query, corpus[p_l + f: p_r])
            if lr > bmv_l:
                bmv_l = lr
                bp_l = p_l + f

            rl = ratio(query, corpus[p_l: p_r - f])
            if rl > bmv_r:
                bmv_r = rl
                bp_r = p_r - f

            rr = ratio(query, corpus[p_l: p_r + f])
            if rr > bmv_r:
                bmv_r = rr
                bp_r = p_r + f

        return bp_l, bp_r, ratio(query, corpus[bp_l : bp_r])

    if not case_sensitive:
        query = query.lower()
        corpus = corpus.lower()

    qlen = len(query)

    if flex >= qlen/2:
        print("Warning: flex exceeds length of query / 2. Setting to default.")
        flex = 3

    match_values = scan_corpus(step)
    pos = index_max(match_values) * step

    pos_left, pos_right, match_value = adjust_left_right_positions()

    return corpus[pos_left: pos_right].strip(), match_value
