import attr


class DongJianError(Exception):
    pass


class DongJianRestartFailedError(DongJianError):
    pass


class DongJianTargetConnectionFailedError(DongJianError):
    pass


class DongJianTargetConnectionReset(DongJianError):
    pass


@attr.s
class DongJianTargetConnectionAborted(DongJianError):
    """
    Raised on `errno.ECONNABORTED`.
    """

    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class DongJianNoSuchTestCase(DongJianError):
    pass


class DongJianRpcError(DongJianError):
    pass


class SullyRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
