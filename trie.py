import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Env variables
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

bearerToken = os.environ.get("BEARER_TOKEN")
tableUrl = os.environ.get("TABLE_URL")

class TrieNode:
    def __init__(self):
        self.children = {}
        self.skyflow_ids = []
        self.is_end_of_word = False


class Trie:
    def __init__(self, is_encrypted=False):
        self.root = TrieNode()
        self.is_encrypted = is_encrypted
        self.encryption_key = os.urandom(32)  # AES-256 key
        self.iv = iv = os.urandom(16)

    def encrypt(self, plaintext):
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(self.iv + encrypted).decode()

    def insert(self, word, skyflow_id):
        word = word.lower()
        node = self.root
        for ch in word:
            key = ch
            if(self.is_encrypted):
                key = self.encrypt(ch)
            
            if key not in node.children:
                node.children[key] = TrieNode()
            node = node.children[key]
        node.skyflow_ids.append(skyflow_id)
        node.is_end_of_word = True

    def collect_words(self, node, prefix):
        words = []
        skyflow_ids = []
        if node.is_end_of_word:
            words.append(prefix)
            skyflow_ids = skyflow_ids + node.skyflow_ids
        for ch, next_node in node.children.items():
            words.extend(self.collect_words(next_node, prefix + ch))
        return words
      
    def collect_ids(self, node, prefix):
        skyflow_ids = []
        if node.is_end_of_word:
            skyflow_ids = skyflow_ids + node.skyflow_ids
        for ch, next_node in node.children.items():
            # key = ch
            # if self.is_encrypted:
            #     key = self.encrypt(ch)
            skyflow_ids = skyflow_ids + self.collect_ids(next_node, prefix + ch)
        return skyflow_ids

    def search_from_node(self, node, word):
        for ch in word:
            key = ch
            if self.is_encrypted:
                key = self.encrypt(ch)
            if key not in node.children:
                return None
            node = node.children[key]
        return node

    def search_substring(self, substring):
        node = self.root
        for i, ch in enumerate(substring):
            key = ch
            if self.is_encrypted:
                key = self.encrypt(ch)
            if key in node.children:
                node = node.children[key]
                matching_node = self.search_from_node(node, substring[i+1:])
                if matching_node:
                    return self.collect_ids(matching_node, substring)
            else:
                print('no key found')
                return []
        return []

    def print_tree(self, node=None, prefix='', level=0):
        if node is None:
            node = self.root
        for ch, next_node in node.children.items():
            print(' ' * level * 2 + ch)
            self.print_tree(next_node, prefix + ch, level + 1)
        if node.is_end_of_word:
            print(' ' * level * 2 + "(end)")
            
            
def print_matching_recods(matches):
    print('Found ' + str(len(matches)) + ' matching records in the vault:\n')
    skyflow_ids = '&'.join(f'skyflow_ids={skyflow_id}' for skyflow_id in matches)
    url = "https://ebfc9bee4242.vault.skyflowapis.com/v1/vaults/n6320d707b6f4705a9e23dd3e966d237/shoppers?redaction=DEFAULT&"+skyflow_ids

    headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {bearerToken}'
                }
    
    response = requests.request("GET", tableUrl, headers=headers)
    response_as_json = response.json()
    
    records = response_as_json['records']
    for record in records:
        print(record)
        print('\n')

def init_trie_with_vault_records(trie, encrypted_trie):
    url = "https://ebfc9bee4242.vault.skyflowapis.com/v1/vaults/n6320d707b6f4705a9e23dd3e966d237/shoppers?redaction=PLAIN_TEXT"

    headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {bearerToken}'
                }
    
    response = requests.request("GET", tableUrl, headers=headers)
    response_as_json = response.json()
    records = response_as_json['records']
    
    for record in records:
        first_name = record['fields']['first_name']
        skyflow_id = record['fields']['skyflow_id']
        print('inserting ' + first_name + ' with skyflow_id = ' + skyflow_id)
        trie.insert(first_name, skyflow_id)
        encrypted_trie.insert(first_name, skyflow_id)


def main():
    trie = Trie()
    encrypted_trie = Trie(True)
    while True:
        command = input(
            "Enter command (init / search <substring> / print / print encrypted / search encrypted <substring> / exit): ").strip().lower()
        if command == "encrypt":
            trie.encrypt_trie()
            print(f"Trie is encrypted.")
        elif command.startswith("search encrypted"):
            substring = command[len("search encrypted "):].strip()
            matches = encrypted_trie.search_substring(substring)
            if matches:
                print_matching_recods(matches)
            else:
                print(f"Substring '{substring}' not found in any word.")
        elif command.startswith("search "):
            substring = command[len("search "):].strip()
            matches = trie.search_substring(substring)
            if matches:
                print_matching_recods(matches)
            else:
                print(f"Substring '{substring}' not found in any word.")
        elif command == "print":
            print("Trie structure:")
            trie.print_tree()
        elif command == "print encrypted":
            print("Trie structure:")
            encrypted_trie.print_tree()
        elif command == "init":
            init_trie_with_vault_records(trie, encrypted_trie)
        elif command == "exit":
            break
        else:
            print("Invalid command. Please try again.")


if __name__ == "__main__":
    main()
