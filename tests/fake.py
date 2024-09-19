__all__ = ["FakeTimestamp"]


class FakeTimestamp:
    __return_value: float

    def __init__(self, return_value: float) -> None:
        self.__return_value = return_value

    def __call__(self) -> float:
        return self.__return_value
