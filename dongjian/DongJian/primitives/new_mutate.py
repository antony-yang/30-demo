from . import interesting_values
import random
import copy

ARITH_MAX = 35


class NewMutation:
    def __init__(
            self,
    ):
        self.use_stacking = 5
        pass

    def random2(self, value: int) -> int:
        if value >= 1:
            return random.randint(0, value - 1)
        else:
            return 0

    def trans_list(self, value: bytes) -> list:
        tmp = []
        for i in range(0, len(value)):
            tmp.append(value[i: i + 1])
        return tmp

    def none_minus(self, value):
        if value < 0:
            return -value
        return value

    def trim_data(self, value: bytes, min_len: int, max_len: int) -> bytes:
        length = len(value)
        # print(length)
        if length < min_len:
            mod = self.random2(3)
            if mod == 0:
                if self.random2(2) == 0:
                    return b'\x00' * (min_len - length) + value
                else:
                    return value + b'\x00' * (min_len - length)
            elif mod == 1:
                if self.random2(2) == 0:
                    return (self.random2(256).to_bytes(1, "big", signed=False)) * (min_len - length) + value
                else:
                    return value + (self.random2(256).to_bytes(1, "big", signed=False)) * (min_len - length)
            else:
                r = self.random2(length)
                ch = value[r: r + 1]
                if self.random2(2) == 0:
                    return ch * (min_len - length) + value
                else:
                    return value + ch * (min_len - length)
        elif min_len <= length <= max_len:
            return value
        else:
            get_at = self.random2(length - max_len + 1)
            return value[get_at: get_at + max_len]

    def generate_no_zero_blk(self, len: int) -> bytes:
        ret = b''
        for j in range(0, len):
            ret += self.random2(256).to_bytes(1, "big", signed=False)
        return ret

    def havok(self, value: bytes) -> bytes:
        self.use_stacking = 1 << (1 + self.random2(7))
        for i in range(0, self.use_stacking):
            mutate_choose = self.random2(17)
            if mutate_choose == 0:
                value = self.flip_bit(value)
            elif mutate_choose == 1:
                value = self.set_byte_to_interesting_value(value)
            elif mutate_choose == 2:
                value = self.set_word_to_interesting_value(value)
            elif mutate_choose == 3:
                value = self.set_dword_to_interesting_value(value)
            elif mutate_choose == 4:
                value = self.randomly_substract_from_byte(value)
            elif mutate_choose == 5:
                value = self.randomly_add_from_byte(value)
            elif mutate_choose == 6:
                value = self.randomly_subtract_from_word(value)
            elif mutate_choose == 7:
                value = self.randomly_add_from_word(value)
            elif mutate_choose == 8:
                value = self.randomly_subtract_from_dword(value)
            elif mutate_choose == 9:
                value = self.randomly_add_from_dword(value)
            elif mutate_choose == 10:
                value = self.set_randbyte_to_randvalue(value)
            elif mutate_choose == 11:
                value = self.del_some_bytes(value)
            elif mutate_choose == 12:
                value = self.del_some_bytes(value)
            elif mutate_choose == 13:
                value = self.clone_bytes(value)
            elif mutate_choose == 14:
                value = self.overwrite_bytes(value)
            elif mutate_choose == 15:
                value = self.overwrite_with_extra(value)
            elif mutate_choose == 16:
                value = self.overwrite_with_extra_len(value)
        ret = value
        return ret

    # 0
    def flip_bit(self, value) -> bytes:
        if len(value) == 0:
            return b''
        tmp = self.trans_list(value)
        length = len(value) << 3
        position = self.random2(length)
        n = int.from_bytes(tmp[position >> 3], "big", signed=False)
        n ^= (128 >> (position & 7))
        tmp[position >> 3] = n.to_bytes(1, "big", signed=False)
        return b''.join(tmp)

    # 1
    def set_byte_to_interesting_value(self, value: bytes) -> bytes:
        if len(value) == 0:
            return b''
        tmp = self.trans_list(value)
        position_orig = self.random2(len(tmp))
        position = self.random2(len(interesting_values.interesting8))
        tmp[position_orig] = interesting_values.interesting8[position].to_bytes(1, "big", signed=True)
        return b''.join(tmp)

    # 2
    def set_word_to_interesting_value(self, value: bytes) -> bytes:
        #  random big or little endian
        if len(value) < 2:
            return value
        else:
            tmp = []
            pos_orig = self.random2(len(value) - 1)
            pos = self.random2(len(interesting_values.interesting16))
            tmp.append(value[0: pos_orig])
            tmp.append(value[pos_orig: pos_orig + 2])
            tmp.append(value[pos_orig + 2: len(value)])
            if self.random2(2) == 1:
                # big endian
                replace = interesting_values.interesting16[pos]
                replace = replace.to_bytes(2, "big", signed=True)
                tmp[1] = replace
            else:
                # little endian
                replace = interesting_values.interesting16[pos]
                replace = replace.to_bytes(2, "little", signed=True)
                tmp[1] = replace
            return b''.join(tmp)

    # 3
    def set_dword_to_interesting_value(self, value: bytes) -> bytes:
        #  random big or little endian
        if len(value) < 4:
            return value
        else:
            tmp = []
            pos_orig = self.random2(len(value) - 3)
            pos = self.random2(len(interesting_values.interesting16))
            tmp.append(value[0: pos_orig])
            tmp.append(value[pos_orig: pos_orig + 4])
            tmp.append(value[pos_orig + 4: len(value)])
            if self.random2(2) == 1:
                # big endian
                replace = interesting_values.interesting16[pos]
                replace = replace.to_bytes(4, "big", signed=True)
                tmp[1] = replace
            else:
                # little endian
                replace = interesting_values.interesting16[pos]
                replace = replace.to_bytes(4, "little", signed=True)
                tmp[1] = replace
            return b''.join(tmp)

    # 4
    def randomly_substract_from_byte(self, value: bytes) -> bytes:
        length = len(value)
        if length == 0:
            return b''
        tmp = self.trans_list(value)
        pos = self.random2(length)
        n = int.from_bytes(tmp[pos], "big", signed=False)
        n -= 1 + self.random2(ARITH_MAX)
        n = self.none_minus(n)
        tmp[pos] = n.to_bytes(1, "big", signed=False)
        return b''.join(tmp)

    # 5
    def randomly_add_from_byte(self, value: bytes) -> bytes:
        length = len(value)
        if length == 0:
            return b''
        tmp = self.trans_list(value)
        pos = self.random2(length)
        n = int.from_bytes(tmp[pos], "big", signed=False)
        n += 1 + self.random2(ARITH_MAX)
        n %= 255
        tmp[pos] = n.to_bytes(1, "big", signed=False)
        return b''.join(tmp)

    # 6
    def randomly_subtract_from_word(self, value: bytes) -> bytes:
        length = len(value)
        if length < 2:
            return value
        tmp = []
        pos = self.random2(length - 1)
        tmp.append(value[0: pos])
        tmp.append(value[pos: pos + 2])
        tmp.append(value[pos + 2: len(value)])
        if self.random2(2) == 1:
            n = int.from_bytes(tmp[1], "big", signed=False)
            n -= 1 + self.random2(ARITH_MAX)
            n = self.none_minus(n)
            tmp[1] = n.to_bytes(2, "big", signed=False)
        else:
            n = int.from_bytes(tmp[1], "little", signed=False)
            n -= 1 + self.random2(ARITH_MAX)
            n = self.none_minus(n)
            tmp[1] = n.to_bytes(2, "little", signed=False)
        return b''.join(tmp)

    # 7
    def randomly_add_from_word(self, value: bytes) -> bytes:
        length = len(value)
        if length < 2:
            return value
        tmp = []
        pos = self.random2(length - 1)
        tmp.append(value[0: pos])
        tmp.append(value[pos: pos + 2])
        tmp.append(value[pos + 2: len(value)])
        if self.random2(2) == 1:
            n = int.from_bytes(tmp[1], "big", signed=False)
            n += (1 + self.random2(ARITH_MAX))
            n %= 65535
            tmp[1] = n.to_bytes(2, "big", signed=False)
        else:
            n = int.from_bytes(tmp[1], "little", signed=False)
            n += (1 + self.random2(ARITH_MAX))
            n %= 65535
            tmp[1] = n.to_bytes(2, "little", signed=False)
        return b''.join(tmp)

    # 8
    def randomly_subtract_from_dword(self, value: bytes) -> bytes:
        length = len(value)
        if length < 4:
            return value
        tmp = []
        pos = self.random2(length - 3)
        tmp.append(value[0: pos])
        tmp.append(value[pos: pos + 4])
        tmp.append(value[pos + 4: len(value)])
        if self.random2(2) == 1:
            n = int.from_bytes(tmp[1], "big", signed=False)
            n -= 1 + self.random2(ARITH_MAX)
            n = self.none_minus(n)
            tmp[1] = n.to_bytes(4, "big", signed=False)
        else:
            n = int.from_bytes(tmp[1], "little", signed=False)
            n -= 1 + self.random2(ARITH_MAX)
            n = self.none_minus(n)
            tmp[1] = n.to_bytes(4, "little", signed=False)
        return b''.join(tmp)

    # 9
    def randomly_add_from_dword(self, value: bytes) -> bytes:
        length = len(value)
        if length < 4:
            return value
        tmp = []
        pos = self.random2(length - 3)
        tmp.append(value[0: pos])
        tmp.append(value[pos: pos + 4])
        tmp.append(value[pos + 4: len(value)])
        if self.random2(2) == 1:
            n = int.from_bytes(tmp[1], "big", signed=False)
            n += (1 + self.random2(ARITH_MAX))
            n %= 4294967295
            tmp[1] = n.to_bytes(4, "big", signed=False)
        else:
            n = int.from_bytes(tmp[1], "little", signed=False)
            n += (1 + self.random2(ARITH_MAX))
            n %= 4294967295
            tmp[1] = n.to_bytes(4, "little", signed=False)
        return b''.join(tmp)

    # 10
    def set_randbyte_to_randvalue(self, value: bytes) -> bytes:
        length = len(value)
        if length == 0:
            return b''
        tmp = self.trans_list(value)
        pos = self.random2(length)
        n = int.from_bytes(tmp[pos], "big", signed=False)
        n ^= 1 + self.random2(255)
        tmp[pos] = n.to_bytes(1, "big", signed=False)
        return b''.join(tmp)

    # 11~12
    def del_some_bytes(self, value: bytes) -> bytes:
        length = len(value)
        if length < 2:
            return value
        tmp = self.trans_list(value)
        del_len = self.random2(length - 1)
        del_from = self.random2(length - del_len + 1)
        for i in range(del_from, del_from + del_len):
            tmp[i] = b''
        return b''.join(tmp)

    # 13
    def clone_bytes(self, value: bytes) -> bytes:
        length = len(value)
        if length == 0:
            return b''
        tmp = []
        prop = self.random2(4)
        clone_len = 0
        clone_from = 0
        clone_to = self.random2(length)
        if prop == 1:
            clone_len = self.random2(length)
            clone_from = self.random2(length - clone_len + 1)
            tmp.append(value[0: clone_to])
            tmp.append(value[clone_from: clone_from + clone_len])
            tmp.append(value[clone_to: length])
        else:
            clone_len = self.random2(4096)
            clone_from = 0
            tmp.append(value[0: clone_to])
            u = self.random2(3)
            if u == 0:
                mid = self.generate_no_zero_blk(clone_len)
            elif u == 1:
                mid = self.random2(256).to_bytes(1, "big", signed=False) * clone_len
            else:
                r = self.random2(length)
                mid = value[r: r + 1] * clone_len
            tmp.append(mid)
            tmp.append(value[clone_to: length])
        return b''.join(tmp)

    # 14
    def overwrite_bytes(self, value: bytes) -> bytes:
        length = len(value)
        if length < 2:
            return value
        tmp = []
        copy_len = self.random2(length - 1)
        copy_from = self.random2(length - copy_len + 1)
        copy_to = self.random2(length - copy_len + 1)
        prop = self.random2(4)
        tmp.append(value[0: copy_to])
        if prop == 0:
            if copy_from != copy_to:
                tmp.append(value[copy_from: copy_from + copy_len])
        else:
            u = self.random2(3)
            if u == 0:
                mid = self.generate_no_zero_blk(copy_len)
            elif u == 1:
                mid = self.random2(256).to_bytes(1, "big", signed=False) * copy_len
            else:
                r = self.random2(length)
                mid = value[r: r + 1] * copy_len
            tmp.append(mid)
        tmp.append(value[copy_to + copy_len: length])
        return b''.join(tmp)

    """
        there are some differences between us and AFL,
        we merge the dictionary and the odds bytes into one,
        so we don't need to handle them,
        in our template fuzz period, we automatic add these odds into
        our dictionary
    """

    # 15
    def overwrite_with_extra(self, value: bytes) -> bytes:
        length = len(value)
        use_extra = self.random2(len(interesting_values.interesting_bytes))
        extra_len = len(interesting_values.interesting_bytes[use_extra])
        if length < extra_len:
            return value
        tmp = []
        insert_at = self.random2(length - extra_len + 1)
        tmp.append(value[0: insert_at])
        tmp.append(interesting_values.interesting_bytes[use_extra])
        tmp.append(value[insert_at + extra_len: length])
        return b''.join(tmp)

    # 16
    def overwrite_with_extra_len(self, value: bytes) -> bytes:
        length = len(value)
        use_extra = self.random2(len(interesting_values.interesting_bytes))
        extra_len = len(interesting_values.interesting_bytes[use_extra])
        # if length < extra_len:
        #     return value
        tmp = []
        insert_at = self.random2(length - extra_len + 1)
        tmp.append(value[0: insert_at])
        tmp.append(interesting_values.interesting_bytes[use_extra])
        tmp.append(value[insert_at: length])
        return b''.join(tmp)