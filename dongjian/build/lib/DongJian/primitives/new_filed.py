
class New:
    def __init__(
            self,
            raw,
            data,
    ):
        self._raw = raw
        self.data = data
        self.name = "new"
        self.start = self._raw.find(self.data)
        self.end = self.start + len(self.data)

    def new_mutate(self):
        from . import new_mutate
        nm = new_mutate.NewMutation()
        value = self._raw
        value = nm.havok(value)
        tmp = []
        if self.start > 0:
            if self.end < len(value) - 1:
                tmp.append(value[0: self.start])
                tmp.append(self.data)
                tmp.append(value[self.end + 1: len(value)])
                value = b''.join(tmp)
        self._raw = value
        return True

    def render(self):
        return self._raw
