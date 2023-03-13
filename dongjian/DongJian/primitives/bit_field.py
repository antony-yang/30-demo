import itertools
import struct
import six
from builtins import range
from past.builtins import map

from .base_primitive import BasePrimitive
from .. import helpers
from ..constants import LITTLE_ENDIAN


def binary_string_to_int(binary):
    """
    Convert a binary string to a decimal number.

    @type  binary: str
    @param binary: Binary string

    @rtype:  int
    @return: Converted bit string
    """

    return int(binary, 2)


def int_to_binary_string(number, bit_width):
    """
    Convert a number to a binary string.

    @type  number:    int
    @param number:    (Optional, def=self._value) Number to convert
    @type  bit_width: int
    @param bit_width: (Optional, def=self.width) Width of bit string

    @rtype:  str
    @return: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


class BitField(BasePrimitive):
    def __init__(
            self,
            value,
            width,
            max_num=None,
            endian=LITTLE_ENDIAN,
            output_format="binary",
            signed=False,
            full_range=False,
            fuzzable=True,
            name=None,
    ):
        """
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:         int
        @param value:         Default integer value
        @type  width:         int
        @param width:         Width of bit fields
        @type  max_num:       int
        @param max_num:       Maximum number to iterate up to
        @type  endian:        chr
        @param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  output_format: str
        @param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  full_range:    bool
        @param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(BitField, self).__init__()

        assert isinstance(value, (six.integer_types, list, tuple)), "value must be an integer, list, or tuple!"
        assert isinstance(width, six.integer_types), "width must be an integer!"

        self._value = self._original_value = value
        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.format = output_format
        self.signed = signed
        self.full_range = full_range
        self._fuzzable = fuzzable
        self._name = name
        self.cyclic_index = 0  # when cycling through non-mutating values

        if not self.max_num:
            self.max_num = binary_string_to_int("1" + "0" * width)

        assert isinstance(self.max_num, six.integer_types), "max_num must be an integer!"

        self.mutate_iter = self._iterate_fuzz_lib()

        # TODO: Add injectable arbitrary bit fields

    def _yield_integer_boundaries(self, integer):
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: int
        @param integer: int to append to fuzz heuristics
        """
        for i in range(-10, 10):
            case = integer + i
            if 0 <= case < self.max_num:
                # some day: if case not in self._user_provided_values
                yield case

    def _iterate_fuzz_lib(self):
        if self.full_range:
            for i in range(0, self.max_num):
                yield i
        else:
            # try only "smart" values.
            interesting_boundaries = [
                0,
                self.max_num // 2,
                self.max_num // 3,
                self.max_num // 4,
                self.max_num // 8,
                self.max_num // 16,
                self.max_num // 32,
                self.max_num,
            ]
            for boundary in interesting_boundaries:
                for v in self._yield_integer_boundaries(boundary):
                    yield v

    def num_mutations(self):
        return sum(1 for _ in self._iterate_fuzz_lib())

    def mutate(self):
        fuzz_complete = False
        # if we've ran out of mutations, raise the completion flag.
        if self._mutant_index == self.num_mutations():
            self._fuzz_complete = True
            fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self._fuzzable or fuzz_complete:
            self._value = self._original_value
            return False

        # update the current value from the fuzz library.
        try:
            # self._value = next(itertools.islice(self._iterate_fuzz_lib(), self._mutant_index, self._mutant_index + 1))
            self._value = next(self.mutate_iter)
        except StopIteration as e:
            return False

        # increment the mutation count.
        self._mutant_index += 1

        return True

    @BasePrimitive.original_value.setter
    def original_value(self, value):
        if self.endian == LITTLE_ENDIAN:
            n = int.from_bytes(value, byteorder="little", signed=False)
        else:
            n = int.from_bytes(value, byteorder="big", signed=False)
        self._original_value = n

    def new_mutate(self):
        if not self._fuzzable:
            self._value = self._original_value
            return False
        # value = self.render()[::-1]
        from . import new_mutate
        tmp = self.render()
        length = len(tmp)
        nm = new_mutate.NewMutation()
        tmp = nm.havok(tmp)
        tmp = nm.trim_data(tmp, length, length)
        value = tmp
        if self.endian == LITTLE_ENDIAN:
            n = int.from_bytes(value, byteorder="little", signed=False)
        else:
            n = int.from_bytes(value, byteorder="big", signed=False)
        self._value = n
        return True

    @property
    def name(self):
        return self._name

    def add_integer_boundaries(self, integer):
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: int
        @param integer: int to append to fuzz heuristics
        """
        for i in range(-10, 10):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self._fuzz_library:
                    self._fuzz_library.append(case)

    def _render(self, value):
        temp = self.render_int(
            value, output_format=self.format, bit_width=self.width, endian=self.endian, signed=self.signed
        )
        return helpers.str_to_bytes(temp)

    @staticmethod
    def render_int(value, output_format, bit_width, endian, signed):
        """
        Convert value to a bit or byte string.

        Args:
            value (int): Value to convert to a byte string.
            output_format (str): "binary" or "ascii"
            bit_width (int): Width of output in bits.
            endian: BIG_ENDIAN or LITTLE_ENDIAN
            signed (bool):

        Returns:
            str: value converted to a byte string
        """
        if output_format == "binary":
            bit_stream = ""
            rendered = b""

            # pad the bit stream to the next byte boundary.
            if bit_width % 8 == 0:
                bit_stream += int_to_binary_string(value, bit_width)
            else:
                bit_stream = "0" * (8 - (bit_width % 8))
                bit_stream += int_to_binary_string(value, bit_width)

            # convert the bit stream from a string of bits into raw bytes.
            for i in range(len(bit_stream) // 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                rendered += struct.pack("B", binary_string_to_int(chunk))

            # if necessary, convert the endianness of the raw bytes.
            if endian == LITTLE_ENDIAN:
                # reverse the bytes
                rendered = rendered[::-1]

            _rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if signed and int_to_binary_string(value, bit_width)[0] == "1":
                max_num = binary_string_to_int("1" + "0" * (bit_width - 1))
                # chop off the sign bit.
                val = value & binary_string_to_int("1" * (bit_width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                _rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                _rendered = "%d" % value
        return _rendered

    def __len__(self):
        if self.format == "binary":
            return self.width // 8
        else:
            return len(str(self._value))

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
