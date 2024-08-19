from hashlib import md5
import random
import argparse

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=<>?/"

MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 8
MEAN_LENGTH = 3.5
STD_LENGTH = 1

def main():
    parser = argparse.ArgumentParser(description="Generate passwords")
    parser.add_argument('-u', '--uniform', type=int, help='length of password')
    parser.add_argument('number', type=int, help='number of passwords to generate')
    args = parser.parse_args()

    num_passwords = args.number
    uniform = args.uniform

    length = round(random.normalvariate(MEAN_LENGTH, STD_LENGTH))
    length = max(MIN_PASSWORD_LENGTH, min(MAX_PASSWORD_LENGTH, length))

    passwords = [
        ''.join(random.choices(CHARSET, k=length if not uniform else uniform))
        for _ in range(num_passwords)
    ]
    
    with open(f'../inputs/{num_passwords}{"u" if uniform else ""}_plain.txt', 'w') as f:
        f.write('\n'.join(passwords))

    passwords_hashed = [md5(password.encode('utf-8')).hexdigest() for password in passwords]

    with open(f'../inputs/{num_passwords}{"u" if uniform else ""}_hashed.txt', 'w') as f:
        f.write('\n'.join(passwords_hashed))

if __name__ == '__main__':
    main()