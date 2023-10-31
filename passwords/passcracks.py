# Used Starting code from Jeff Ondich
'''
    conversions.py
    Jeff Ondich, 6 May 2022

    Shows how to compute a SHA-256 hash and manipulate the
    relevant Python types.

    Note that when you want to do a new hash, you need to
    call hashlib.sha256() again to get a fresh sha256 object.
'''
import hashlib
import binascii


def print_test():
    password = 'moose' # type=string
    print(f'password ({type(password)}): {password}')

    encoded_password = password.encode('utf-8') # type=bytes
    print(f'encodedPassword ({type(encoded_password)}): {encoded_password}')

    hasher = hashlib.sha256(encoded_password)
    digest = hasher.digest() # type=bytes
    print(f'digest ({type(digest)}): {digest}')

    digest_as_hex = binascii.hexlify(digest) # weirdly, still type=bytes
    print(f'digest_as_hex ({type(digest_as_hex)}): {digest_as_hex}')

    digest_as_hex_string = digest_as_hex.decode('utf-8') # type=string
    print(f'digest_as_hex_string ({type(digest_as_hex_string)}): {digest_as_hex_string}')

hash_counter = 0

def dictionary_to_string(dictionary):
    output_string = ""
    for key in dictionary:
        output_string += key + ":" + dictionary[key] + "\n"
    return output_string

def word_to_hash_value(word):
    encoded_word = word.encode('utf-8')
    hasher = hashlib.sha256(encoded_word)
    digest = hasher.digest()
    digest_as_hex = binascii.hexlify(digest)
    digest_as_hex_string = digest_as_hex.decode('utf-8')

    global hash_counter
    hash_counter += 1
    return digest_as_hex_string

def get_before_colon(word, start_index):
    extracted_word = ""
    for current_index in range(start_index, len(word)):
        current_char = word[current_index]
        if(current_char != ":"):
            extracted_word += current_char
        else:
            return extracted_word, current_index + 1
    return current_char, current_index + 1

def get_username_and_password(word):
    username, next_index = get_before_colon(word, 0)
    password = get_before_colon(word, next_index)[0]
    return username, password

def get_username_and_salted_password(word):
    username, next_index = get_before_colon(word, 0)
    salt_and_password = get_before_colon(word, next_index)[0]
    salt = salt_and_password[3:11]
    password = salt_and_password[12:]
    return username, salt, password

def get_password_dictionary(password_list):
    password_dictionary = {}
    for password_string in password_list:
        username, password = get_username_and_password(password_string)
        password_dictionary[username] = password
    return password_dictionary

def get_password_dictionary_2(password_list):
    password_dictionary = {}
    for password_string in password_list:
        username, password = get_username_and_password(password_string)
        password_dictionary[password] = username
    return password_dictionary

def get_salted_password_dictionary(password_list):
    password_dictionary = {}
    for password_string in password_list:
        username, salt, password = get_username_and_salted_password(password_string)
        password_dictionary[username] = (salt, password)
    return password_dictionary

def get_word_hash_dictionary(word_list):
    word_hash_dictionary = {}
    for word in word_list:
        hash_value = word_to_hash_value(word)
        word_hash_dictionary[hash_value] = word
    return word_hash_dictionary

def get_cracked_password_dictionary(password_dictionary, word_hash_dictionary):
    cracked_password_dictionary = {}
    for username in password_dictionary:
        password = password_dictionary[username]
        cracked_password = word_hash_dictionary[password]
        cracked_password_dictionary[username] = cracked_password
    return cracked_password_dictionary

def attempt_update_value(dictionary, new_word):
    hashed_word = word_to_hash_value(new_word)
    if hashed_word in dictionary:
        cracked2 = open('cracked2.txt', 'a')
        cracked2.write(dictionary[hashed_word] + ":" + new_word + "\n")
        cracked2.close()

def get_word_subset(word_list):
    word_subset = []
    for word in word_list:
        if word[0] == "b":
            return word_subset
        else:
            word_subset.append(word)

def write_cracked_dictionary_2(password_dictionary, word_list):
    cracked2 = open('cracked2.txt', 'w')
    cracked2.write("")
    cracked2.close()
    
    attempt_update_value(password_dictionary, "marmot")
    word_subset = get_word_subset(word_list)
    for word_1 in word_subset:
        for word_2 in word_list:
            combined_word = word_1 + word_2
            attempt_update_value(password_dictionary, combined_word)

def get_individual_salted_password(salt, password, word_list):
    for word in word_list:
        salt_and_word = salt + word
        hash_value = word_to_hash_value(salt_and_word)
        if hash_value == password:
            return word
        
def get_cracked_salted_password_dictionary(password_dictionary, word_list):
    cracked_password_dictionary = {}
    for username in password_dictionary:
        salt = password_dictionary[username][0]
        password = password_dictionary[username][1]
        cracked_password_dictionary[username] = get_individual_salted_password(salt, password, word_list)
    return cracked_password_dictionary

def crack_password_1():
    passwords_1 = open("passwords1.txt", "r").read()
    passwords_1 = passwords_1.split("\n")
    usernames_and_passwords_1 = get_password_dictionary(passwords_1)

    words_1 = [line.strip().lower() for line in open('words1.txt')]
    hash_word_dictionary_1 = get_word_hash_dictionary(words_1)

    cracked_dictionary_1 = get_cracked_password_dictionary(usernames_and_passwords_1, hash_word_dictionary_1)

    cracked_password_string = dictionary_to_string(cracked_dictionary_1)
    cracked1 = open('cracked1.txt', 'w')
    cracked1.write(cracked_password_string)
    cracked1.close()

def crack_password_2():
    passwords_2 = open("passwords2.txt", "r").read()
    passwords_2 = passwords_2.split("\n")

    usernames_and_passwords_2 = get_password_dictionary_2(passwords_2)

    words_1 = [line.strip().lower() for line in open('words1.txt')]

    write_cracked_dictionary_2(usernames_and_passwords_2, words_1)

def crack_password_3():
    passwords_3 = open("passwords3.txt", "r").read()
    passwords_3 = passwords_3.split("\n")
    usernames_and_passwords_3 = get_salted_password_dictionary(passwords_3)

    words_1 = [line.strip().lower() for line in open('words1.txt')]

    cracked_dictionary_3 = get_cracked_salted_password_dictionary(usernames_and_passwords_3, words_1)

    cracked_password_string = dictionary_to_string(cracked_dictionary_3)
    cracked3 = open('cracked3.txt', 'w')
    cracked3.write(cracked_password_string)
    cracked3.close()

    
test_string = "$5$16307550$15e000d5278984fe7c19c91ee51efb62143e30b66b279890404b18f3d38a5a4a"

crack_password_1()
#crack_password_2()
#crack_password_3()

print(hash_counter)
