f = open("8.txt", "r")
cipher_list = f.read().split('\n')
f.close()

block_width = 32 #bits -> 16 bytes
line = 0
for cipher in cipher_list:
    dict = {}
    totalChunks = len(cipher)/block_width
    for i in range(0,len(cipher),block_width):
        c = cipher[i:i+block_width]
        if (c in dict.keys()):
            dict[c] += 1
        else:
            dict[c] = 1

    if (len(dict) < totalChunks):
        print("Found it!")
        print("cipher.: %s" % cipher)
        print("line...: %d" % line)

        print()
        print("Chunk -> Frequency:")
        for k, v in dict.items():
            print("%s -> %d" % (k, v))
    line += 1


