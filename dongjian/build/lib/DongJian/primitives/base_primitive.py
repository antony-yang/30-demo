import abc

from .. import helpers
from ..ifuzzable import IFuzzable


class BasePrimitive(IFuzzable):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    @abc.abstractproperty
    def name(self):
        pass

    @property
    def mutant_index(self):
        return self._mutant_index

    @property
    def fuzzable(self):
        return self._fuzzable

    @property
    def original_value(self):
        return self._render(self._original_value)

    @original_value.setter
    def original_value(self, value):
        self._original_value = value

    def __init__(self):
        self._fuzzable = True  # flag controlling whether or not the given primitive is to be fuzzed.
        self._mutant_index = 0  # current mutation index into the fuzz library.
        self._original_value = None  # original value of primitive.
        self._original_value_rendered = None  # original value as rendered

        self._fuzz_complete = False  # this flag is raised when the mutations are exhausted.
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self._rendered = b""  # rendered value of primitive.
        self._value = None  # current value of primitive.

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
        self._value = self._fuzz_library[self._mutant_index]

        # increment the mutation count.
        self._mutant_index += 1

        return True

    def new_mutate(self):
        if not self._fuzzable:
            self._value = self._original_value
            return False
        from . import new_mutate
        tmp = self.render()
        length = len(tmp)
        nm = new_mutate.NewMutation()
        tmp = nm.havok(tmp)
        tmp = nm.trim_data(tmp, 0, length)
        self._value = tmp
        return True

    def num_mutations(self):
        return len(self._fuzz_library)

    def render(self):
        """
        Render this instance's value.

        Returns:
            bytes: Rendered value
        """

        value = self._render(self._value)
        self._rendered = value
        return helpers.str_to_bytes(value)

    def _render(self, value):
        """
        Render an arbitrary value.

        Args:
            value: Value to render.

        Returns:
            bytes: Rendered value
        """
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)

    def reset(self):
        self._fuzz_complete = False
        self._mutant_index = 0
        self._value = self._original_value

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, repr(self._value))

    def __len__(self):
        return len(self._value)

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
