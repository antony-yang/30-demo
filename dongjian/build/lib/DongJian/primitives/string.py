import itertools
import math
import random

import six
from past.builtins import range

from .base_primitive import BasePrimitive
from .. import helpers


class String(BasePrimitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    _fuzz_library = [
            "",
            # strings ripped from spike (and some others I added)
            "/",  # cwd
            "F",  # stru
            "S",  # mode
            "Z",  # mode
            "A",  # type
            "I",  # type
            "L 8",  # type
            "1111.xml",  # retr,stor
            "System Volume Information",  # cwd
            "/.:/" + "A" * 5000 + "\x00\x00",
            "/.../" + "B" * 5000 + "\x00\x00",
            "/.../.../.../.../.../.../.../.../.../.../",
            "\\..\\..\\..\\..\\..\\..\\..\\",
            "/../../../../../../../../../../../../etc/passwd",
            "/../../../../../../../../../../../../boot.ini",
            "..:..:..:..:..:..:..:..:..:..:..:..:..:",
            "\\\\*",
            "\\\\?\\",
            "/\\" * 5000,
            "/." * 5000,
            "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
            "%01%02%03%04%0a%0d%0aADSF",
            "%01%02%03@%04%0a%0d%0aADSF",
            "\x01\x02\x03\x04",
            "/%00/",
            "%00/",
            "%00",
            "%u0000",
            "%\xfe\xf0%\x00\xff",
            "%\xfe\xf0%\x01\xff" * 20,
            # format strings.
            "%n" * 100,
            "%n" * 500,
            '"%n"' * 500,
            "%s" * 100,
            "%s" * 500,
            '"%s"' * 500,
            # command injection.
            "|touch /tmp/SULLEY",
            ";touch /tmp/SULLEY;",
            "|notepad",
            ";notepad;",
            "\nnotepad\n",
            "|reboot",
            ";reboot;",
            "\nreboot\n",
            # fuzzdb command injection
            "a)|reboot;",
            "CMD=$'reboot';$CMD",
            "a;reboot",
            "a)|reboot",
            "|reboot;",
            "'reboot'",
            '^CMD=$"reboot";$CMD',
            "`reboot`",
            "%0DCMD=$'reboot';$CMD",
            "/index.html|reboot|",
            "%0a reboot %0a",
            "|reboot|",
            "||reboot;",
            ";reboot/n",
            "id",
            ";id",
            "a;reboot|",
            "&reboot&",
            "%0Areboot",
            "a);reboot",
            "$;reboot",
            '&CMD=$"reboot";$CMD',
            '&&CMD=$"reboot";$CMD',
            ";reboot",
            "id;",
            ";reboot;",
            "&CMD=$'reboot';$CMD",
            "& reboot &",
            "; reboot",
            "&&CMD=$'reboot';$CMD",
            "reboot",
            "^CMD=$'reboot';$CMD",
            ";CMD=$'reboot';$CMD",
            "|reboot",
            "<reboot;",
            "FAIL||reboot",
            "a);reboot|",
            '%0DCMD=$"reboot";$CMD',
            "reboot|",
            "%0Areboot%0A",
            "a;reboot;",
            'CMD=$"reboot";$CMD',
            "&&reboot",
            "||reboot|",
            "&&reboot&&",
            "^reboot",
            ";|reboot|",
            "|CMD=$'reboot';$CMD",
            "|nid",
            "&reboot",
            "a|reboot",
            "<reboot%0A",
            'FAIL||CMD=$"reboot";$CMD',
            "$(reboot)",
            "<reboot%0D",
            ";reboot|",
            "id|",
            "%0Dreboot",
            "%0Areboot%0A",
            "%0Dreboot%0D",
            ";system('reboot')",
            '|CMD=$"reboot";$CMD',
            ';CMD=$"reboot";$CMD',
            "<reboot",
            "a);reboot;",
            "& reboot",
            "| reboot",
            "FAIL||CMD=$'reboot';$CMD",
            '<!--#exec cmd="reboot"-->',
            "reboot;",
            # some binary strings.
            "\xde\xad\xbe\xef",
            "\xde\xad\xbe\xef" * 10,
            "\xde\xad\xbe\xef" * 100,
            "\xde\xad\xbe\xef" * 1000,
            "\xde\xad\xbe\xef" * 10000,
            # miscellaneous.
            "\r\n" * 100,
            "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
        ]
    long_string_seeds = [
        "C",
        "1",
        "<",
        ">",
        "'",
        '"',
        "/",
        "\\",
        "?",
        "=",
        "a=",
        "&",
        ".",
        ",",
        "(",
        ")",
        "]",
        "[",
        "%",
        "*",
        "-",
        "+",
        "{",
        "}",
        "\x14",
        "\x00",
        "\xFE",  # expands to 4 characters under utf1
        "\xFF",  # expands to 4 characters under utf1
    ]

    _long_string_lengths = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]
    _long_string_deltas = [-2, -1, 0, 1, 2]
    _extra_long_string_lengths = [99999, 100000, 500000, 1000000]
    _variable_mutation_multipliers = [2, 10, 100]

    def __init__(self, value, size=-1, padding=b"\x00", encoding="ascii", fuzzable=True, max_len=None, name=None):
        """
        Primitive that cycles through a library of "bad" strings. The class variable 'fuzz_library' contains a list of
        smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
        the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
        each instantiated primitive.

        @type  value:    str
        @param value:    Default string value
        @type  size:     int
        @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  chr
        @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: str
        @param encoding: (Optional, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:  int
        @param max_len:  (Optional, def=-1) Maximum string length
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(String, self).__init__()

        if isinstance(value, bytes):
            self._original_value = value
        else:
            self._original_value = value.encode(encoding=encoding)
        self._value = self._original_value
        self.size = size
        self.max_len = max_len
        if self.size > -1:
            self.max_len = self.size
        if len(padding) == 1:
            self.padding = padding
        else:
            self.padding = b"\x00"
        self.encoding = encoding
        self._fuzzable = fuzzable
        self._name = name

        self.mutate_iter = self.mutations(self._original_value)

        self._static_num_mutations = None
        self.random_indices = {}

        local_random = random.Random(0)  # We want constant random numbers to generate reproducible test cases
        previous_length = 0
        # For every length add a random number of random indices to the random_indices dict. Prevent duplicates by
        # adding only indices in between previous_length and current length.
        for length in self._long_string_lengths:
            self.random_indices[length] = local_random.sample(
                range(previous_length, length), local_random.randint(1, self._long_string_lengths[0])
            )
            previous_length = length

    @property
    def name(self):
        return self._name

    def _yield_long_strings(self, sequences):
        """
        Given a sequence, yield a number of selectively chosen strings lengths of the given sequence.

        @type  sequences: list(str)
        @param sequences: Sequence to repeat for creation of fuzz strings.
        """
        for sequence in sequences:
            for size in [
                length + delta
                for length, delta in itertools.product(self._long_string_lengths, self._long_string_deltas)
            ]:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            for size in self._extra_long_string_lengths:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            if self.max_len is not None:
                data = sequence * math.ceil(self.max_len / len(sequence))
                yield data

        for size in self._long_string_lengths:
            if self.max_len is None or size <= self.max_len:
                s = "D" * size
                for loc in self.random_indices[size]:
                    yield s[:loc] + "\x00" + s[loc + 1 :]  # Replace character at loc with terminator
            else:
                break

    def _yield_variable_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            value = default_value * length
            if value not in self._fuzz_library:
                yield value
                if self.max_len is not None and len(value) >= self.max_len:
                    break

    def _adjust_mutation_for_size(self, fuzz_value):
        if self.max_len is not None and self.max_len < len(fuzz_value):
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value

    def mutations(self, default_value):
        last_val = None

        for val in itertools.chain(
                self._fuzz_library,
                self._yield_variable_mutations(default_value),
                self._yield_long_strings(self.long_string_seeds),
        ):
            current_val = self._adjust_mutation_for_size(val)
            if last_val == current_val:
                continue
            last_val = current_val
            yield current_val

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False

            # update the current value from the fuzz library.
            try:
                # self._value = next(
                #     itertools.islice(self.mutations(self._original_value), self._mutant_index, self._mutant_index + 1))
                self._value = next(self.mutate_iter)
            except StopIteration as e:
                return False

            # increment the mutation count.
            self._mutant_index += 1

            # if the size parameter is disabled, done.
            if self.size <= -1:
                return True

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self._value) > self.size:
                continue
            else:
                return True

    def new_mutate(self):
        if not self._fuzzable:
            self._value = self._original_value
            return False
        from . import new_mutate
        tmp = self.render()
        nm = new_mutate.NewMutation()
        tmp = nm.havok(tmp)
        if self.max_len is None:
            self._value = tmp
        else:
            tmp = nm.trim_data(tmp, 0, self.max_len)
            self._value = tmp
        return True

    def num_mutations(self):
        variable_num_mutations = sum(1 for _ in self._yield_variable_mutations(default_value=self.original_value))
        if self._static_num_mutations is None:
            self._static_num_mutations = sum(1 for _ in self.mutations(default_value=""))
        return self._static_num_mutations + variable_num_mutations

    def _render(self, value):
        """
        Render string value, properly padded.
        """
        if isinstance(value, six.text_type):
            value = helpers.str_to_bytes(value)

        # pad undersized library items.
        if len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return helpers.str_to_bytes(value)

