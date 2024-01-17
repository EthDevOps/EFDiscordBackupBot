import base64
import csv
import glob
import hashlib
import json
import os
from datetime import datetime
import requests
import boto3
import nextcord
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from gnupg import GPG

key_fingerprints = []
gpg = GPG()
S3_CLIENT = None
SIGNING_KEY = None

class ConfigurationError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class CryptographyError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def get_ephemeral_path():
    ephemeral_path = os.getenv('EPHEMERAL_PATH')
    if ephemeral_path is None:
        ephemeral_path = '.'
    return ephemeral_path


def is_s3_enabled():
    return os.getenv('S3_ENABLED') == '1'


def s3_bucket():
    return os.getenv('S3_BUCKET')


def init_s3():
    # Read Env
    s3_access_key = os.getenv('S3_ACCESS_KEY')
    s3_secret_key = os.getenv('S3_SECRET_KEY')
    s3_endpoint = os.getenv('S3_ENDPOINT')

    # Setup
    if is_s3_enabled():
        # Prepare S3 access
        if s3_bucket() is None:
            raise ConfigurationError('S3 enabled but S3_BUCKET not set.')

        if s3_access_key is None:
            raise ConfigurationError('S3 enabled but S3_ACCESS_KEY not set.')

        if s3_secret_key is None:
            raise ConfigurationError('S3 enabled but S3_SECRET_KEY not set.')

        if s3_endpoint is None:
            raise ConfigurationError('S3 enabled but S3_ENDPOINT not set.')

        return boto3.client(
            service_name='s3',
            aws_access_key_id=s3_access_key,
            aws_secret_access_key=s3_secret_key,
            endpoint_url=s3_endpoint,
        )
    return None


def hash_string(msg):
    """
    Hashes a string with SHA256

    :param msg: The string to hash
    :return: 1. Hex string of the hash, 2. hash bytes
    """
    h = hashlib.sha256(msg.encode())
    return h.hexdigest(), h.digest()


def extract_message(message):
    """
    Extracts information and attachments from a discord message and returns it as a dictionary.

    :param message: The discord message object from which to extract information.
    :return: A dictionary containing information from the message.
    """
    parent = ''
    if hasattr(message.channel, "parent"):
        parent = message.channel.parent.name

    attachments = []
    # process any attachments/files
    for attach in message.attachments:
        # Download file
        resp = requests.get(attach.url, timeout=30)
        resp.raise_for_status()

        attachments.append({
            'type': attach.content_type,
            'origin_name': attach.filename,
            'content': base64.b64encode(resp.content).decode()
        })

    backup_msg = {
        'author': {
            'id': message.author.id,
            'name': message.author.name,
            'global_name': message.author.global_name
        },
        'server': {
            'id': message.guild.id,
            'name': message.guild.name
        },
        'channel': {
            'id': message.channel.id,
            'name': message.channel.name,
        },
        'category': message.channel.category.name,
        'parent': parent,
        'content': message.content,
        'created_at': message.created_at.isoformat(),
        'attachments': attachments

    }
    return backup_msg


def write_to_storage(backup_msg):
    """
    Write the given message to file storage.
    see Readme for more information.

    :param backup_msg: The backup message to write.
    :return: None
    """
    # stringify json
    json_msg = json.dumps(backup_msg)

    # encrypt with gpg
    enc_msg = gpg.encrypt(json_msg.encode('utf8'), key_fingerprints)

    if not enc_msg.ok:
        print(f'Encryption failed: {enc_msg.status}')
        raise CryptographyError('Unable to encrypt')

    # hash and sign msg
    enc_hash_str, enc_hash_b = hash_string(str(enc_msg))
    signature = SIGNING_KEY.sign(enc_hash_b).hex()

    manifest_path, _ = get_manifest_path(backup_msg["server"]["id"], backup_msg["channel"]["id"])

    # Write to manifest
    with open(manifest_path, 'a', encoding='utf-8') as manifest_file:
        writer = csv.writer(manifest_file)
        # Date/Time of message, msg hash, signature
        writer.writerow([backup_msg['created_at'], enc_hash_str, signature])

    # write to msg file
    if is_s3_enabled():
        S3_CLIENT.put_object(Bucket=s3_bucket(), Key=f'messages/{enc_hash_str}', Body=str(enc_msg))
    else:
        msg_path = os.path.join(get_ephemeral_path(), f'{enc_hash_str}.msg')
        with open(msg_path,'w', encoding='utf-8') as msg_file:
            msg_file.write(str(enc_msg))
    print(f'Message written: {enc_hash_str}')


def get_signing_key():
    """
    Loads the private key used for signing from disk. If it doesn't exist it will be generated.

    :return: The private key used for signing.
    """
    keyfile = os.getenv('SIGN_KEY_PEM')

    if keyfile is None:
        raise ConfigurationError('Signing key not configured. Please set SIGN_KEY_PEM.')

    # Verify file extension
    if os.path.splitext(keyfile)[1] != '.pem':
        raise ConfigurationError('Signing key file not a pem file. make sure the extension is pem.')

    if os.path.exists(keyfile):
        print(f'Loading signing key from {keyfile}...')
        # To reload the key:
        with open(keyfile, "rb") as file_key:
            private_key = serialization.load_pem_private_key(
                file_key.read(),
                password=None)
    else:
        print(f'No signing key found. Generating and writing to {keyfile}...')
        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()

        # create file with specific permissions
        fd = os.open(keyfile, os.O_CREAT, mode=0o600)
        os.close(fd)

        # Save private key to disk
        with open(keyfile, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save punlic key to disk
        pub_path = keyfile.replace('pem','pub')
        with open(pub_path, "wb") as key_file:
            key_file.write(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    return private_key


def seal_manifest(guild_id, channel_id):
    """
    This method seals the manifest file for a guild and channel by hashing the IDs,
    loading the manifest contents,
    generating a signature for the manifest, and writing the signature to a seal file.

    :param guild_id: the ID of the guild
    :param channel_id: the ID of the channel
    :return: None
    """
    manifest_path, _ = get_manifest_path(guild_id, channel_id)
    seal_path = manifest_path.replace('.manifest','.seal')

    # load the manifest contents
    if not os.path.exists(manifest_path):
        print(f'No manifest for {guild_id} - {channel_id}. Likly empty channel. Skipping seal.')
        return

    with open(manifest_path, 'r', encoding='utf-8') as manifest:
        man_str = manifest.read()
        _, manifest_hash = hash_string(man_str)
        man_signature = SIGNING_KEY.sign(manifest_hash).hex()
        with open(seal_path, 'w', encoding='utf-8') as seal_file:
            seal_file.write(man_signature)


def get_manifest_path(guild_id, channel_id):
    channel_hash, _ = hash_string(str(channel_id))
    guild_hash, _ = hash_string(str(guild_id))
    return (os.path.join(get_ephemeral_path(), f'{guild_hash}-{channel_hash}.manifest'),
            f'manifests/{guild_hash}-{channel_hash}')


def get_manifest_seal_path(guild_id, channel_id):
    channel_hash, _ = hash_string(str(channel_id))
    guild_hash, _ = hash_string(str(guild_id))
    return (os.path.join(get_ephemeral_path(), f'{guild_hash}-{channel_hash}.seal'),
            f'manifests/seals/{guild_hash}-{channel_hash}')


async def backup_channel(channel, last_message_id):
    """
    Backs up the messages of a given channel.

    :param channel: Discord channel object.
    :param last_message_id: The id of the last message in the channel to start from.
    :return: The id of the last message backed up.
    """
    # Load last message as a starting point
    after = None
    if last_message_id > 0:
        after = await channel.fetch_message(last_message_id)

    # download manifest from S3
    manifest_path, s3_manifest_path = get_manifest_path(channel.guild.id, channel.id)

    if is_s3_enabled():
        try:
            S3_CLIENT.head_object(Bucket=s3_bucket(), Key=s3_manifest_path)
            S3_CLIENT.download_file(Bucket=s3_bucket(),
                                    Filename=manifest_path,
                                    Key=s3_manifest_path)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                # The object does not exist.
                pass
            else:
                # Something else has gone wrong.
                raise

    # pull all messages since message
    while True:
        messages = await channel.history(limit=100, after=after, oldest_first=True).flatten()
        if not messages:
            break

        # Process messages
        for message in messages:
            backup_msg = extract_message(message)
            write_to_storage(backup_msg)

        after = messages[-1]

    # Seal the manifest
    seal_manifest(channel.guild.id, channel.id)

    # upload to S3
    if is_s3_enabled():
        # upload manifest and seal
        manifest_seal_path, s3_manifest_seal_path = get_manifest_seal_path(channel.guild.id, channel.id)
        S3_CLIENT.upload_file(manifest_path, s3_bucket(), s3_manifest_path)
        S3_CLIENT.upload_file(manifest_seal_path, s3_bucket(), s3_manifest_seal_path)

    return after.id


def get_loc_path(channel):
    """
    Gets the path for a channels loc file

    :param channel: The channel for which to generate the location path.
    :return: The location path for the given channel in the format 'guild_hash-channel_hash.loc'.
    """
    guild_hash, _ = hash_string(str(channel.guild.id))
    channel_hash, _ = hash_string(str(channel.id))
    return (os.path.join(get_ephemeral_path(), f'{guild_hash}-{channel_hash}.loc'),
            f'locations/{guild_hash}-{channel_hash}')


async def get_last_message_id(channel):
    """
    Retrieve the ID of the last message in a channel from a loc file

    :param channel: The channel to retrieve the last message ID from.
    :type channel: nextcord.channel.Channel
    :return: The ID of the last message in the channel.
    :rtype: int
    """
    last_msg_id = -1
    loc_path, loc_s3_path = get_loc_path(channel)

    # If S3 is enabled go directly to S3
    if is_s3_enabled():
        try:
            loc_obj = S3_CLIENT.get_object(Bucket=s3_bucket(), Key=loc_s3_path)
            initial_content = loc_obj['Body'].read().decode()
            last_msg_id = int(initial_content)
        except ClientError:
            print("The location is non existent on S3.")

    else:
        if os.path.exists(loc_path):
            with open(loc_path, 'r', encoding='utf-8') as f:
                f_content = f.read()
                last_msg_id = int(f_content)
    return last_msg_id


async def set_last_message_id(channel, new_last_msg_id):
    """
    Write the new last message ID to the loc file for the given channel.

    :param channel: The channel for which the last message ID needs to be set.
    :param new_last_msg_id: The new last message ID to be set.
    :return: None
    """
    loc_path, loc_s3_path = get_loc_path(channel)
    if is_s3_enabled():
        S3_CLIENT.put_object(Bucket=s3_bucket(), Key=loc_s3_path, Body=str(new_last_msg_id))
    else:
        with open(loc_path, "w", encoding='utf-8') as file:
            file.write(str(new_last_msg_id))


def generate_directory_file(target_channels, current_datetime):
    """
    This method generates a directory file based on the servers and channels the bot has access to.
    see Readme about directory files for more info.

    :param target_channels: A list of target channels to include in the directory file.
    :return: None
    """
    iso8601_format = current_datetime.isoformat().replace(':', '-').replace('.', '-')

    directory = []
    for channel in target_channels:
        # Only intressted in text channels
        if not isinstance(channel, nextcord.TextChannel):
            continue

        # Get the server or create new one
        servers = [srv for srv in directory if srv['server_id'] == channel.guild.id]
        server = servers[0] if servers else {
            "server_id": channel.guild.id,
            "server_id_hashed": hash_string(str(channel.guild.id))[0],
            "server_name": channel.guild.name,
            "channels": []
        }

        # create channels
        dir_channel = {
            "channel_id": channel.id,
            "channel_id_hashed": hash_string(str(channel.id))[0],
            "channel_name": channel.name,
            "threads": []
        }

        # Add threads
        for thread in channel.threads:
            dir_channel["threads"].append({
                "thread_id": thread.id,
                "thread_id_hashed": hash_string(str(thread.id))[0],
                "thread_name": thread.name
            })

        # add channel to directory
        server["channels"].append(dir_channel)
        if not servers:
            directory.append(server)

    # Write directory to file
    dir_json = json.dumps(directory, indent=4)

    # encrypt with gpg
    enc_msg = gpg.encrypt(dir_json.encode('utf8'), key_fingerprints)

    if not enc_msg.ok:
        print(f'Encryption failed: {enc_msg.status}')
        raise CryptographyError('Unable to encrypt')

    # Write directory to storage
    if is_s3_enabled():
        S3_CLIENT.put_object(Bucket=s3_bucket(), Key=f'directories/{iso8601_format}', Body=str(enc_msg))
    else:
        with open(os.path.join(get_ephemeral_path(), f'{iso8601_format}.dir'), 'w', encoding='utf-8') as file:
            file.write(str(enc_msg))

    # generate seal
    _, manifest_hash = hash_string(str(enc_msg))
    man_signature = SIGNING_KEY.sign(manifest_hash).hex()

    # write the directory to storage
    if is_s3_enabled():
        S3_CLIENT.put_object(Bucket=s3_bucket(), Key=f'directories/seals/{iso8601_format}', Body=man_signature)
    else:
        with open(os.path.join(get_ephemeral_path(), f'{iso8601_format}.dirseal'), 'w', encoding='utf-8') as seal_file:
            seal_file.write(man_signature)


def load_gpg_keys():
    print('Loading GPG keys...')
    gpg_key_dir = os.getenv('GPG_KEY_DIR')
    if gpg_key_dir is None:
        raise ConfigurationError('No GPG key directory set. Please set GPG_KEY_DIR.')
    key_files = glob.glob(os.path.join(gpg_key_dir, '*.asc'))
    imported_keys = [gpg.import_keys_file(key_file) for key_file in key_files]

    # Trust keys
    # Set trust for imported keys
    for key in imported_keys:
        keyid = key.fingerprints[0]
        trust_result = gpg.trust_keys([keyid], 'TRUST_ULTIMATE')
        print(f'GPG key imported and trusted: {keyid} => {trust_result}')

    # Get the fingerprints of the imported keys
    return [result.fingerprints[0] for result in imported_keys]


def send_heartbeat(start=False):
    url = os.getenv('HEARTBEAT_URL')

    if url is None:
        print('No HEARTBEAT_URL set. Monitoring disabled.')
        return

    if start:
        url = url + '/start'
    # Send a start signal to heartbeat
    try:
        requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        # If the network request fails for any reason, we don't want
        # it to prevent the main job from running
        pass


if __name__ == '__main__':
    # Main starting
    print('EF Backup Bot starting...')

    # Read config from env
    TOKEN = os.getenv('DISCORD_TOKEN')
    if TOKEN is None:
        raise ConfigurationError('No discord token set. Please set DISCORD_TOKEN.')

    send_heartbeat(start=True)

    # init S3
    S3_CLIENT = init_s3()

    # prepare gpg
    key_fingerprints = load_gpg_keys()

    # load the signing key
    SIGNING_KEY = get_signing_key()

    # Prepare discord connection
    intents = nextcord.Intents.default()
    intents.message_content = True
    client = nextcord.Client(intents=intents)

    @client.event
    async def on_ready():
        """
        This method is an event handler for the `on_ready` event in a Discord bot.
        Used here to trigger the backup run after login.

        :return: None
        """
        print(f'Bot has logged in to discord as {client.user}')

        # Grab servers and channels
        target_channels = client.get_all_channels()

        # Build directory file
        generate_directory_file(client.get_all_channels(), datetime.now())

        # Backup channels
        for channel in target_channels:
            # Only intressted in text channels
            if not isinstance(channel, nextcord.TextChannel):
                continue

            print(f'Backing up Channel {channel.id} on {channel.guild.id}')

            # Backup channels
            last_msg_id = await get_last_message_id(channel)
            new_last_msg_id = await backup_channel(channel, last_msg_id)
            await set_last_message_id(channel, new_last_msg_id)

            # Backup threads in channel
            for thread in channel.threads:
                print(f'Backing up Thread {thread.id} in Channel {channel.id} on {channel.guild.id}')

                last_msg_id = await get_last_message_id(thread)
                new_last_msg_id = await backup_channel(thread, last_msg_id)
                await set_last_message_id(thread, new_last_msg_id)

        # Quit when done
        print('Notifying the heartbeat check...')
        send_heartbeat()

        print('Done. exiting.')
        await client.close()

    # run the bot - still in main
    client.run(TOKEN)
