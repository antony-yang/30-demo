import functools
import itertools
import operator

from funcy import compose

from .base_primitive import BasePrimitive
from .. import helpers


class Bytes(BasePrimitive):
    # This binary strings will always included as testcases.
    _fuzz_library = [
        b"",
        b"\x00",
        b"\xFF",
        b"A" * 10,
        b"A" * 100,
        b"A" * 1000,
        b"A" * 5000,
        b"A" * 10000,
        b"A" * 100000,
    ]

    # from https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_debug_values
    _magic_debug_values = [
        b"\x00\x00\x81#",
        b"\x00\xfa\xca\xde",
        b"\x1b\xad\xb0\x02",
        b"\x8b\xad\xf0\r",
        b"\xa5\xa5\xa5\xa5",
        b"\xa5",
        b"\xab\xab\xab\xab",
        b"\xab\xad\xba\xbe",
        b"\xab\xba\xba\xbe",
        b"\xab\xad\xca\xfe",
        b"\xb1k\x00\xb5",
        b"\xba\xad\xf0\r",
        b"\xba\xaa\xaa\xad",
        b'\xba\xd2""',
        b"\xba\xdb\xad\xba\xdb\xad",
        b"\xba\xdc\x0f\xfe\xe0\xdd\xf0\r",
        b"\xba\xdd\xca\xfe",
        b"\xbb\xad\xbe\xef",
        b"\xbe\xef\xca\xce",
        b"\xc0\x00\x10\xff",
        b"\xca\xfe\xba\xbe",
        b"\xca\xfe\xd0\r",
        b"\xca\xfe\xfe\xed",
        b"\xcc\xcc\xcc\xcc",
        b"\xcd\xcd\xcd\xcd",
        b"\r\x15\xea^",
        b"\xdd\xdd\xdd\xdd",
        b"\xde\xad\x10\xcc",
        b"\xde\xad\xba\xbe",
        b"\xde\xad\xbe\xef",
        b"\xde\xad\xca\xfe",
        b"\xde\xad\xc0\xde",
        b"\xde\xad\xfa\x11",
        b"\xde\xad\xf0\r",
        b"\xde\xfe\xc8\xed",
        b"\xde\xad\xde\xad",
        b"\xeb\xeb\xeb\xeb",
        b"\xfa\xde\xde\xad",
        b"\xfd\xfd\xfd\xfd",
        b"\xfe\xe1\xde\xad",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xee\xfe\xee",
    ]

    # This is a list of "interesting" 1,2 and 4 byte binary strings.
    # The lists are used to replace each block of 1, 2 or 4 byte in the original
    # value with each of those "interesting" values.
    _fuzz_strings_1byte = [b"\x00", b"\x01", b"\x7F", b"\x80", b"\xFF"] + [
        i for i in _magic_debug_values if len(i) == 1
    ]

    _fuzz_strings_2byte = [
        b"\x00\x00",
        b"\x01\x00",
        b"\x00\x01",
        b"\x7F\xFF",
        b"\xFF\x7F",
        b"\xFE\xFF",
        b"\xFF\xFE",
        b"\xFF\xFF",
    ] + [i for i in _magic_debug_values if len(i) == 2]

    _fuzz_strings_4byte = [
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x01",
        b"\x01\x00\x00\x00",
        b"\x7F\xFF\xFF\xFF",
        b"\xFF\xFF\xFF\x7F",
        b"\xFE\xFF\xFF\xFF",
        b"\xFF\xFF\xFF\xFE",
        b"\xFF\xFF\xFF\xFF",
    ] + [i for i in _magic_debug_values if len(i) == 4]

    _mutators_of_default_value = [

        functools.partial(operator.mul, 2),
        functools.partial(operator.mul, 10),
        functools.partial(operator.mul, 100),
    ]

    def __init__(self, value, size=None, padding=b"\x00", fuzzable=True, max_len=None, name=None):
        """
        Primitive that fuzzes a binary byte string with arbitrary length.

        @type  value:      bytes
        @param value:      Default string value
        @type  size:       int
        @param size:       (Optional, def=None) Static size of this field, leave None for dynamic.
        @type  padding:    chr
        @param padding:    (Optional, def=b"\\x00") Value to use as padding to fill static field size.
        @type  fuzzable:   bool
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:    int
        @param max_len:    (Optional, def=None) Maximum string length
        @type  name:       str
        @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Bytes, self).__init__()

        assert isinstance(value, bytes)
        self._original_value = value
        self._value = self._original_value
        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.padding = padding
        self._fuzzable = fuzzable
        self._name = name

        self.mutate_iter = self.mutations(self._original_value)

    @property
    def name(self):
        return self._name

    def mutations(self, default_value):
        for fuzz_value in self._iterate_fuzz_cases(default_value):
            if callable(fuzz_value):
                ret = compose(self._adjust_mutation_for_size, fuzz_value)
                yield ret(self._original_value)
            else:
                yield self._adjust_mutation_for_size(fuzz_value=fuzz_value)

    def _adjust_mutation_for_size(self, fuzz_value):
        if self.size is not None:
            if len(fuzz_value) > self.size:
                return fuzz_value[: self.max_len]
            else:
                return fuzz_value + self.padding * (self.size - len(fuzz_value))
        elif self.max_len is not None and len(fuzz_value) > self.max_len:
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value

    def _iterate_fuzz_cases(self, default_value):
        for fuzz_value in self._fuzz_library:
            yield fuzz_value
        for fuzz_value in self._mutators_of_default_value:
            yield fuzz_value
        for fuzz_value in self._magic_debug_values:
            yield fuzz_value
        for i in range(0, len(default_value)):
            for fuzz_bytes in self._fuzz_strings_1byte:

                def f(value):
                    if i < len(value):
                        return value[:i] + fuzz_bytes + value[i + 1 :]
                    else:
                        return value

                yield f
        for i in range(0, len(default_value) - 1):
            for fuzz_bytes in self._fuzz_strings_2byte:

                def f(value):
                    if i < len(value) - 1:
                        return value[:i] + fuzz_bytes + value[i + 2 :]
                    else:
                        return value

                yield f

        for i in range(0, len(default_value) - 3):
            for fuzz_bytes in self._fuzz_strings_4byte:

                def f(value):
                    if i < len(value) - 3:
                        return value[:i] + fuzz_bytes + value[i + 4 :]
                    else:
                        return value

                yield f

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        while True:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False
            try:
                # self._value = next(itertools.islice(self.mutations(self._original_value), self._mutant_index, self._mutant_index + 1))
                self._value = next(self.mutate_iter)
            except StopIteration as e:
                return False

            # increment the mutation count.
            self._mutant_index += 1

            # check if the current testcase aligns
            if self.size is not None and len(self._value) > self.size:
                continue  # too long, skip this one
            if self.max_len is not None and len(self._value) > self.max_len:
                # truncate the current value
                self._value = self._value[: self.max_len]

            # _value has now been mutated and therefore we return True to indicate success
            return True

    def new_mutate(self):
        if not self._fuzzable:
            self._value = self._original_value
            return False
        from . import new_mutate
        tmp = self.render()
        nm = new_mutate.NewMutation()
        tmp = nm.havok(tmp)
        if self.max_len is not None:
            tmp = nm.trim_data(tmp, 0, self.max_len)
        self._value = tmp
        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        return sum(
            (
                len(self._fuzz_library),
                len(self._mutators_of_default_value),
                len(self._magic_debug_values),
                len(self._fuzz_strings_1byte) * max(0, len(self.original_value) - 0),
                len(self._fuzz_strings_2byte) * max(0, len(self.original_value) - 1),
                len(self._fuzz_strings_4byte) * max(0, len(self.original_value) - 3),
            )
        )

    def _render(self, value):
        """
        Render string value, properly padded.
        """

        value = helpers.str_to_bytes(value)

        # if size is set, then pad undersized values.
        if self.size is not None:
            value += self.padding * (self.size - len(value))

        return helpers.str_to_bytes(value)
