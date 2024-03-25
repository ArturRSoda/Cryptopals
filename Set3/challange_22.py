from utils import MT19937
from time import time, sleep
from random import randint



def main() -> None:
    seed = randint(40, 1000) + int(time()) + randint(40, 1000)
    it = MT19937(32, seed).genrand_int()

    print(seed)
    sleep(5)

    guesSeed = int(time())
    while True:

        if (MT19937(32, guesSeed).genrand_int() == it):
            print("original seed =", seed)
            print("discoverd seed =", guesSeed)
            return
        guesSeed += 1

main()
