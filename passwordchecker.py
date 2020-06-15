# This python program checks if a given password is safe to use or not
# It uses pwned API for the password safety check
import requests
import hashlib
import sys


def pwned_api_check(password):  # Creating a SHA1 password using hashlib module
    sha1password = hashlib.sha1(password.encode(
        'utf-8')).hexdigest().upper()  # Required hashing format
    # We need to send only first five characters to API for security
    firstFiveCharacters, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(firstFiveCharacters)
    # print(response)
    return check_password_leaks(response, tail)

# Check for matching counts from the API
def check_password_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for tail, count in hashes:
        if tail == hash_to_check:
            return count
    return 0


def request_api_data(query_char):  # Requesting for data from API
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # print(res)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching:{res.status_code}, Check API')
    return res



def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f"There are {count} of password breaches in the past for this password:{password}.. Refrain from using this password :(")
        else:
            print("Safe password to use :)")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
