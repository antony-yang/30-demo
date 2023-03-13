
from DongJian import *

if __name__ == "__main__":
    nm = NewMutation()
    # n = b"\x23"
    # print(int.from_bytes(n, "big", signed=False))
    # print(int.from_bytes(n, "little", signed=False))
    # m = 36
    # print(m.to_bytes(1, "big", signed=False))
    # print(m.to_bytes(1, "little", signed=False))

    for i in range(0, 10000):
        init = b''
        length = nm.random2(1024)
        for j in range(0, length):
            init += nm.random2(256).to_bytes(1, "big", signed=False)
        print(init.hex())
        # print(nm.flip_bit(init))
        # print(nm.set_byte_to_interesting_value(init))
        # print(nm.set_word_to_interesting_value(init))
        # print(nm.set_dword_to_interesting_value(init))
        # print(nm.set_randbyte_to_randvalue(init))
        # print(nm.randomly_add_from_byte(init))
        # print(nm.randomly_add_from_word(init))
        # print(nm.randomly_add_from_dword(init))
        # print(nm.randomly_substract_from_byte(init))
        # print(nm.randomly_subtract_from_word(init))
        # print(nm.randomly_subtract_from_dword(init))
        # print(nm.del_some_bytes(init))
        # print(nm.clone_bytes(init))
        # print(nm.overwrite_bytes(init).hex())
        # print(nm.overwrite_with_extra(init).hex())
        # print(nm.overwrite_with_extra_len(init).hex())
        res = nm.havok(init)
        print(res.hex())
        res = nm.trim_data(res, 10, 20)
        print(res.hex())
        print()