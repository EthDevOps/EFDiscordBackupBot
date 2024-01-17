# EF Discord Backup Bot

This bot can join a Discord server and then will start taking secure backups .

## Configuration

The following environment variables need to be set:

- `DISCORD_TOKEN` - The authentication Token of the Bot from the Discord developer portal
- `GPG_KEY_DIR` - Directory containing the PGP/GPG public keys (see [Cryptography](#cryptography) below)
- `SIGN_KEY_PEM` - Path to the PEM file containing the ED25519 private key used to sign each message
- `EPHEMERAL_PATH` - working directory to use during on disk file operations
- `HEARTBEAT_URL` - A url to ping with a `GET` request to indicate a successful backup run

For enabling a S3-compatible storage backend use the following environment variables to configure:

- `S3_ENABLED` - set to `1` if you want to use S3 storage
- `S3_ENDPOINT` - set to your S3 endpoint
- `S3_BUCKET` - set to the name of your bucket 
- `S3_ACCESS_KEY` - Username or `aws_access_key_id`
- `S3_SECRET_KEY` - Password or `aws_secret_access_key`

## Cryptography

The main goal is to never write anything to disk/storage that contains message content or has structural data like channel names/id or server names/ids.
To further guarantee integrity of each message, the bot will sign each message with its own ED25519 key. That key is the only sensitive key used by the bot.

### Message encryption

Each message gets encrypted with the PGP/GPG public key passed to the bot via the environment variables (see [Configuration](#configuration)).
The message will be represented in other stored files only by the hash of the ciphertext.

### Message signatures

The bot will sign the hash of the ciphertext with its ED25519 key. That signature will be written out-of-bounds to the manifest file (see [Manifest format](#manifest-file))

**The ED25519 key is considered sensitive**

Leakage of that key will allow to tamper with the messages by replacing the ciphertext with the attackers ciphertext.

### Directory encryption

Each directory file is encrypted with the PGP/GPG public key. 

### Hashes

To not have any linkable data on disk, all server and channel id's used by the [Manifest](#message-files) and [Directory](#directory-files) files are SHA256 hashes of those IDs.
The only way to re-create the relations between servers, Channels and messages is to either know and hash the IDs, or by consulting the [Directory file](#directory-files)

## Storage layout

The storage is seperated into:
- Message files
- Manifest files
- Directory files
- Location files
- Seal files

In S3 mode only the manifest files will be briefly on disk. Everything else will directly go to S3.
The S3 structure is noted in the file format definitions.

### Message Files

Each message is stored in its own encrypted file. The filename is the SHA256 hash of the files contents with the extension `.msg`.
The encrypted message file does not bear any markers towards the server or channel it originated from.

Messages will have the following key in S3: `messages/<SHA256-MESSAGE-HASH>`

The file contains the following message properties:
All properties are from the time of grabbing the msg the first time.

```json
{
    "author": {
        "id": "<Discord ID of the User>",
        "name": "<Name of the User on that Server>",
        "global_name": "<Global name of the user>"
    },
    "server": {
        "id": "<Discord ID of the Server>",
        "name": "<Name of the Server>"
    },
    "channel": {
        "id": "<Discord ID of the Channel>",
        "name": "<Name of the Channel>"
    },
    "category": "<Name of the Category>",
    "parent": "<Name of the Channels parent (mainly for threads)>",
    "content": "<Message text content>",
    "created_at": "<Message creation time on Discord in ISO8601 format>",
    "attachments": [
      {
        "type": "<Content type of the attachment (eg. image/jpg)",
        "origin_name": "<Orginal filename>",
        "content": "<Base64 encoded content of the file>"
      }
    ]
}
```

Notes:
- Attachments are only filled when there are actual files attached to the message
- No backup taken time in the format to ensure a stable hash of the message

### Manifest file

The manifest files contain the list a list of all messages per server and channel (threads are considered separate channels).
They are simple CSV files with the following format per row:

- Discord created at time in ISO8601 format
- SHA256 hash of the message
- ED25519 signature of the message hash

The filename format is `<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>.manifest`
Manifests will have the following key in S3: `manifests/<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>`

### Seal files

Each manifest and directory will be signed by the bot after a backup run. This way any tamper with the manifest or directory can be detected by verifying the seal against the manifest/directory content.
The seal file only contains the ED25519 signature against the hashed content of the manifest/directory.

The filename format is:
- for manifests: `<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>.seal`
- for directories: `<ISO8601-timestamp>.dirseal`

The S3 key format is:
- Manifests seals: `manifests/seals/<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>`
- Directory seals: `directories/seals/<Run timestamp in ISO8601>`

### Location file

Contains the last discord message id, backed up in the channel.
This is the only file that would contain a reference back to Discord.

The filename format is `<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>.loc`
The S3 key format is: `locations/<SHA256-hash-of-Server-ID>-<SHA256-hash-of-Channel-ID>`

### Directory files

The Bot will create a directory file per run, which contains a JSON structure for all servers, channels and threads it had access to during that run.
The directory file is named `<Run timestamp in ISO8601>.dir` and is GPG encrypted.

The S3 key format is: `directories/<Run timestamp in ISO8601>`

The reason to have a directory file per run, is because the bot is not able to decrypt any data it has encrypted using the PGP public keys provided.
The directory has to be encrypted to not leak the server structure, channel and thread names.

Format of the directory file:

```json
[
  {
    "server_id": "<Discord ID of the Server>",
    "server_id_hashed": "<SHA256 hash of server_id>",
    "server_name": "<Name of the Server>",
    "channels": [
      {
        "channel_id": "<Discord ID of the Channel>",
        "channel_id_hashed": "<SHA256 hash of channel_id>",
        "channel_name": "<Name of the Channel>",
        "threads": [
          {
            "thread_id": "<Discord ID of the thread>",
            "thread_id_hashed": "<SHA256 hash of thread_id>",
            "thread_name": "<Name of the thread>"
          }
        ]
      }
    ]
  }
]

```

## Restore/Reconstruction

*NOTE: This process is how to do it manually. There will be a restore tool in the future.*

With the manifest it is possible to reconstruct the channel conversations based on date and time.

Reconstruction should follow these steps:
- Use a [Directory File](#directory-files) from around the time you want to restore data
  - Decrypt the file with the PGP private key
  - Find the server and channel in question and note down the **hashed** IDs. For threads note down the **hashed** thread id instead of the channel id
- Find the manifest for the channel/thread using the hashed ids
- Open the manifest and grab the message hashes and signatures
- Grab all message files in question
- Verify integrity of the message files
  - run `sha256sum` and compare against with the filename
  - verify the signature by running a signature check against the ED25519 public key of the bot and the message hash
- Decrypt the messages


## Current Limitations/Issues

- The seal mechanism re-opens the manifest file after a successful run against the Server/Channel combination. An external process could tamper with the manifest between finishing the backup and creating the seal. *This risk is currently accepted*
- Location files contain a discord reference to the last message in that channel
  - atm @elasticroentgen thinks the attack vector is limited
  - alternative would be to store a datetime range and a hash of the message id and first search for that
