# Encrypted Prefix Search

This is a proof of concept for supporting encrypted prefix searching in a Skyflow vault. The app creates an encrypted trie based on data in a vault. Then you can search against the vault data using plaintext queries, but the search is performed without decrypting any data.

To test this, you need a .env file that contains a valid Skyflow bearer token and a table URL. The trie assumes that there's a column called first_name in the Skyflow vault table.

.env file contains:
* BEARER_TOKEN
* TABLE_URL
