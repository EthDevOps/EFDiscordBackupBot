import base64
import datetime
import os

import nextcord
from cryptography.hazmat.primitives.asymmetric import ed25519
import main
import pytest


def is_base64_encoded(string):
    try:
        decoded = base64.b64decode(string)
        if isinstance(decoded, bytes):
            return True
    except:
        pass
    return False


class TestPaths:
    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6.loc'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f.loc'
        ]
    ])
    def test_get_loc_path(self,mocker,channel_id, guild_id, expected_path_loc, monkeypatch):
        monkeypatch.setenv("EPHEMERAL_PATH", "./")
        channel_mock = mocker.Mock()
        channel_mock.id = channel_id
        channel_mock.guild.id = guild_id

        path_loc, _ = main.get_loc_path(channel_mock)
        assert path_loc == expected_path_loc

    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            'locations/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            'locations/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f'
        ]
    ])
    def test_get_loc_s3(self,mocker,channel_id, guild_id, expected_path_loc, monkeypatch):
        monkeypatch.setenv("EPHEMERAL_PATH", "./")
        channel_mock = mocker.Mock()
        channel_mock.id = channel_id
        channel_mock.guild.id = guild_id

        _, s3_loc = main.get_loc_path(channel_mock)
        assert s3_loc == expected_path_loc

    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6.manifest'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f.manifest'
        ]
    ])
    def test_get_manifest_path(self,channel_id, guild_id, expected_path_loc):
        main.EPHEMERAL_PATH = "./"
        path_loc, _ = main.get_manifest_path(guild_id, channel_id)
        assert path_loc == expected_path_loc

    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            'manifests/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            'manifests/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f'
        ]
    ])
    def test_get_manifest_s3(self,channel_id, guild_id, expected_path_loc):
        main.EPHEMERAL_PATH = "./"
        _, s3_loc = main.get_manifest_path(guild_id, channel_id)
        assert s3_loc == expected_path_loc

    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6.seal'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            './38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f.seal'
        ]
    ])
    def test_get_manifest_seal_path(self,  channel_id, guild_id, expected_path_loc):
        main.EPHEMERAL_PATH = "./"
        path_loc, _ = main.get_manifest_seal_path(guild_id, channel_id)
        assert path_loc == expected_path_loc

    @pytest.mark.parametrize("channel_id, guild_id, expected_path_loc", [
        [
            1194636226960035892,
            1194636226041479298,
            'manifests/seals/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e74deb2daee135e0bdfc98d276a43d758af37a12afa8cdf5c4ca4aa9af933aa6'
        ],
        [
            1194923425324617778,
            1194636226041479298,
            'manifests/seals/38db8582a710659583b9e1878e5c4fa96983292b13908824dd64dba7737de6e4-e88257514b2e0049279d50793b0ff55d6da824d793093ee47df1925205b6385f'
        ]
    ])
    def test_get_manifest_seal_s3(self, channel_id, guild_id, expected_path_loc):
        main.EPHEMERAL_PATH = "./"
        _, s3_loc = main.get_manifest_seal_path(guild_id, channel_id)
        assert s3_loc == expected_path_loc


class TestConfiguration:

    @pytest.mark.parametrize("s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint", [
        ["1", "the-bucket", "12345-access", "12345-secret", "http://localhost:9000"],
    ])
    def test_successful_s3_init(self, monkeypatch, s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint):
        with monkeypatch.context() as m:
            # prep env
            m.setenv("S3_ENABLED", s3enabled)
            m.setenv("S3_BUCKET", s3bucket)
            m.setenv("S3_ACCESS_KEY", s3accesskey)
            m.setenv("S3_SECRET_KEY", s3secretkey)
            m.setenv("S3_ENDPOINT", s3endpoint)

            s3_obj = main.init_s3()

            assert s3_obj is not None
            assert s3_obj.meta.endpoint_url == s3endpoint
            assert s3_obj.meta.region_name == "us-east-1"

    @pytest.mark.parametrize("s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint", [
        ["0", "the-bucket", "12345-access", "12345-secret", "http://localhost:9000"],
    ])
    def test_disabled_s3_init(self, monkeypatch, s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint):
        with monkeypatch.context() as m:
            # prep env
            m.setenv("S3_ENABLED", s3enabled)
            m.setenv("S3_BUCKET", s3bucket)
            m.setenv("S3_ACCESS_KEY", s3accesskey)
            m.setenv("S3_SECRET_KEY", s3secretkey)
            m.setenv("S3_ENDPOINT", s3endpoint)

            s3_obj = main.init_s3()
            assert s3_obj is None

    @pytest.mark.parametrize("s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint, expException", [
        ["1", None, "12345-access", "12345-secret", "http://localhost:9000", "S3 enabled but S3_BUCKET not set."],
        ["1", "bucket", None, "12345-secret", "http://localhost:9000", "S3 enabled but S3_ACCESS_KEY not set."],
        ["1", "bucket", "12345-access", None, "http://localhost:9000", "S3 enabled but S3_SECRET_KEY not set."],
        ["1", "bucket", "12345-access", "12345-secret", None, "S3 enabled but S3_ENDPOINT not set."],
    ])
    def test_failed_s3_init(self, monkeypatch, s3enabled, s3bucket, s3accesskey, s3secretkey, s3endpoint, expException):
        with monkeypatch.context() as m:
            # prep env
            m.setenv("S3_ENABLED", s3enabled)
            if s3bucket is not None:
                m.setenv("S3_BUCKET", s3bucket)
            if s3accesskey is not None:
                m.setenv("S3_ACCESS_KEY", s3accesskey)
            if s3secretkey is not None:
                m.setenv("S3_SECRET_KEY", s3secretkey)
            if s3endpoint is not None:
                m.setenv("S3_ENDPOINT", s3endpoint)

            with pytest.raises(Exception, match=expException):
                main.init_s3()


class TestMisc:
    @pytest.mark.parametrize("hash_input, expected", [
        ["hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"],
    ])
    def test_hash_string(self, hash_input, expected):
        r_str, r_bytes = main.hash_string(hash_input)
        assert r_str == expected

    @pytest.mark.asyncio
    async def test_last_message_id(self,monkeypatch,tmp_path,mocker):
        with monkeypatch.context() as m:
            msg_id = 123456543453
            m.setenv("EPHEMERAL_PATH", str(tmp_path.absolute()))
            channel_mock = mocker.Mock()
            channel_mock.id = 1234
            channel_mock.guild.id = 5678

            # Get empty id
            empty_channel = await main.get_last_message_id(channel_mock)
            assert empty_channel == -1

            # store an id
            await main.set_last_message_id(channel_mock, msg_id)

            # recall id
            non_empty_channel = await main.get_last_message_id(channel_mock)
            assert non_empty_channel == msg_id

class TestMessage:
    def test_extract_basic_message(self, mocker):

        utc_date = datetime.datetime.utcnow()
        expected_iso_date = utc_date.isoformat()

        mock_msg = mocker.Mock()
        mock_msg.attachments = []
        mock_msg.author.id = 12345
        mock_msg.author.name = 'Mr. Test on Server'
        mock_msg.author.global_name = 'Mr. Test is Global'
        mock_msg.guild.id = 56789
        mock_msg.guild.name = "The Servers Name"
        mock_msg.channel.id = 13579
        mock_msg.channel.name = "The Channel Name"
        mock_msg.channel.category.name = "The Channel Category"
        mock_msg.content = "Hello World! This is a fun test!"
        mock_msg.created_at = utc_date

        # make sure no parent exists
        del mock_msg.channel.parent

        message = main.extract_message(mock_msg)

        # see if everything made it into the message
        assert message['author']['id'] == mock_msg.author.id
        assert message['author']['name'] == mock_msg.author.name
        assert message['author']['global_name'] == mock_msg.author.global_name
        assert message['server']['id'] == mock_msg.guild.id
        assert message['server']['name'] == mock_msg.guild.name
        assert message['channel']['id'] == mock_msg.channel.id
        assert message['channel']['name'] == mock_msg.channel.name
        assert message['category'] == mock_msg.channel.category.name
        assert message['content'] == mock_msg.content
        assert message['created_at'] == expected_iso_date
        assert message['parent'] == ''
        assert len(message['attachments']) == 0

    def test_extract_message_with_parent(self, mocker):

        utc_date = datetime.datetime.utcnow()
        expected_iso_date = utc_date.isoformat()

        mock_msg = mocker.Mock()
        mock_msg.attachments = []
        mock_msg.author.id = 12345
        mock_msg.author.name = 'Mr. Test on Server'
        mock_msg.author.global_name = 'Mr. Test is Global'
        mock_msg.guild.id = 56789
        mock_msg.guild.name = "The Servers Name"
        mock_msg.channel.id = 13579
        mock_msg.channel.name = "The Channel Name"
        mock_msg.channel.category.name = "The Channel Category"
        mock_msg.content = "Hello World! This is a fun test!"
        mock_msg.created_at = utc_date
        mock_msg.channel.parent.name = "Parent Channel"

        message = main.extract_message(mock_msg)

        # see if everything made it into the message
        assert message['author']['id'] == mock_msg.author.id
        assert message['author']['name'] == mock_msg.author.name
        assert message['author']['global_name'] == mock_msg.author.global_name
        assert message['server']['id'] == mock_msg.guild.id
        assert message['server']['name'] == mock_msg.guild.name
        assert message['channel']['id'] == mock_msg.channel.id
        assert message['channel']['name'] == mock_msg.channel.name
        assert message['category'] == mock_msg.channel.category.name
        assert message['content'] == mock_msg.content
        assert message['created_at'] == expected_iso_date
        assert message['parent'] == mock_msg.channel.parent.name
        assert len(message['attachments']) == 0

    def test_extract_message_with_attachment(self, mocker):
        # this is using a real attachment

        utc_date = datetime.datetime.utcnow()
        expected_iso_date = utc_date.isoformat()

        mock_attach = mocker.Mock()
        mock_attach.content_type = 'image/jpeg'
        mock_attach.filename = 'some-image.jpg'
        mock_attach.url = 'https://cdn.discordapp.com/attachments/1194636226960035892/1194637333845254144/8-Co4JPO3JEypnyGC.png?ex=65b113b7&is=659e9eb7&hm=abff144dfa9c75be4ec91130ffd35fbbf16ffd7a12d0373cd11f35418ab273d5&'

        mock_msg = mocker.Mock()
        mock_msg.attachments = [mock_attach]
        mock_msg.author.id = 12345
        mock_msg.author.name = 'Mr. Test on Server'
        mock_msg.author.global_name = 'Mr. Test is Global'
        mock_msg.guild.id = 56789
        mock_msg.guild.name = "The Servers Name"
        mock_msg.channel.id = 13579
        mock_msg.channel.name = "The Channel Name"
        mock_msg.channel.category.name = "The Channel Category"
        mock_msg.content = "Hello World! This is a fun test!"
        mock_msg.created_at = utc_date

        message = main.extract_message(mock_msg)

        # see if everything made it into the message
        assert message['author']['id'] == mock_msg.author.id
        assert message['author']['name'] == mock_msg.author.name
        assert message['author']['global_name'] == mock_msg.author.global_name
        assert message['server']['id'] == mock_msg.guild.id
        assert message['server']['name'] == mock_msg.guild.name
        assert message['channel']['id'] == mock_msg.channel.id
        assert message['channel']['name'] == mock_msg.channel.name
        assert message['category'] == mock_msg.channel.category.name
        assert message['content'] == mock_msg.content
        assert message['created_at'] == expected_iso_date
        assert len(message['attachments']) == 1
        assert message['attachments'][0]['type'] == mock_attach.content_type
        assert message['attachments'][0]['origin_name'] == mock_attach.filename
        assert is_base64_encoded(message['attachments'][0]['content'])


class TestSigning:
    def test_load_sign_key(self, tmp_path, monkeypatch):
        with monkeypatch.context() as m:
            key_file = tmp_path / 'priv_key.pem'
            m.setenv('SIGN_KEY_PEM', str(key_file.absolute()))

            # Should generate a new signing key
            priv_key = main.get_signing_key()

            # check ifs an ED25519 private key
            assert isinstance(priv_key, ed25519.Ed25519PrivateKey)

            # check if the pubkey was generated
            assert os.path.exists(str(key_file.absolute()).replace('.pem','.pub'))

            # check if the perms are correct
            key_file_stat = os.stat(str(key_file.absolute()))
            assert key_file_stat.st_mode == 0o100600

            # Should load the key from disk
            priv_key_second = main.get_signing_key()

            # should be the same key - compare pubkeys
            assert priv_key.public_key() == priv_key_second.public_key()

    @pytest.mark.parametrize('filename, expException',[
        ['key.foo', 'Signing key file not a pem file. make sure the extension is pem.'],
        [None, 'Signing key not configured. Please set SIGN_KEY_PEM.']
    ])
    def test_load_sign_key_fail(self, tmp_path, monkeypatch, filename, expException):
        with monkeypatch.context() as m:
            if filename is not None:
                key_file = tmp_path / filename
                m.setenv('SIGN_KEY_PEM', str(key_file.absolute()))

            # Should generate a new signing key
            with pytest.raises(Exception, match=expException):
                main.get_signing_key()


class TestStorage:
    def test_write_to_storage_fail_encrypt_no_keys(self, tmp_path, monkeypatch):
        with monkeypatch.context() as m:
            # message doesn't need to conform to format completely
            dt_iso = datetime.datetime.utcnow().isoformat()
            msg = {
                'content': 'hello world',
                'author': 'Testy McTestface',
                'server': {
                    'id': 1234
                },
                'channel': {
                    'id': 1234
                },
                'created_at': dt_iso
            }

            # set the ephemeral path
            m.setenv('EPHEMERAL_PATH', str(tmp_path))

            # No GPG keys loaded so it should fail here
            with pytest.raises(Exception, match="No recipients specified with asymmetric encryption"):
                main.write_to_storage(msg)

    def test_write_to_storage(self, tmp_path, monkeypatch):
        with monkeypatch.context() as m:
            test_id = 1234
            hash_for_id = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"

            # message doesn't need to conform to format completely
            dt_iso = datetime.datetime.utcnow().isoformat()
            msg = {
                'content': 'hello world',
                'author': 'Testy McTestface',
                'server': {
                    'id': test_id
                },
                'channel': {
                    'id': test_id
                },
                'created_at': dt_iso
            }

            # set the ephemeral path
            m.setenv('EPHEMERAL_PATH', str(tmp_path))

            # generate a signing key
            key_file = tmp_path / 'priv_key.pem'
            m.setenv('SIGN_KEY_PEM', str(key_file.absolute()))
            main.SIGNING_KEY = main.get_signing_key()

            # load a GPG key
            pub_key = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
    
    mDMEZZ6XXxYJKwYBBAHaRw8BAQdAea3323zBNgy12RVKkCWWgfDe5vSLW3R9/6LS
    pqE/hxG0MUdQRyB0ZXN0IGtleSAoT05MWSBGT1IgVEVTVElORykgPG1hcmt1c0B0
    ZXN0Lm9yZz6IkwQTFgoAOxYhBMuek9p7pwAmbyYg1qWXo028DaarBQJlnpdfAhsD
    BQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKWXo028DaarUU8BAOyAmxed
    yWBHajYaEoyn0wfSEGIFVCXatsvcbYpL6hc+AQCrn/t+oC/OqrO4HWPhQDAEgYtW
    9TWOC3A6CYyodYdPD7g4BGWel18SCisGAQQBl1UBBQEBB0DLccDTMTVh0a7Su94Z
    ktDBAzTjYzQ5j2sxKe/OkK2VGQMBCAeIeAQYFgoAIBYhBMuek9p7pwAmbyYg1qWX
    o028DaarBQJlnpdfAhsMAAoJEKWXo028DaarD+EA/0SIgap5bj9FqE+TwVNILLuO
    UiwX/3AQaMi36RJ9oZYKAP9gIkwaL/m0Xu8WQiUNkATCHFsmauptqQw5V8GkSp0l
    Ag==
    =IhBg
    -----END PGP PUBLIC KEY BLOCK-----
    '''

            m.setenv('GPG_KEY_DIR', str(tmp_path.absolute()))
            gpg_pub_key = tmp_path / 'gpg_pub_key.asc'
            gpg_pub_key.write_text(pub_key)

            main.key_fingerprints = main.load_gpg_keys()

            main.write_to_storage(msg)

            # a manifest should be in the tmp path now
            result_manifest_path = tmp_path / f'{hash_for_id}-{hash_for_id}.manifest'
            assert os.path.exists(result_manifest_path)

            # read manifest
            with open(result_manifest_path, 'r') as f:
                manifest_content = f.read()
            manifest_fields = manifest_content.split(',')

            # we expect 3 fields in the manifest
            assert len(manifest_fields) == 3

            # we expect the first to be the iso date of the message
            assert manifest_fields[0] == dt_iso

            # check if the msg file exists
            msg_hash = manifest_fields[1]

            # Check if the filename is correct
            msg_path = tmp_path / f'{msg_hash}.msg'
            assert os.path.exists(str(msg_path.absolute()))

    def test_write_directory_file(self, tmp_path, monkeypatch, mocker):
        with monkeypatch.context() as m:
            # disable the test for nextcord.TextChannel
            mocker.patch('__main__.isinstance', return_value=True)

            # set the ephemeral path
            m.setenv('EPHEMERAL_PATH', str(tmp_path))

            # generate a signing key
            key_file = tmp_path / 'priv_key.pem'
            m.setenv('SIGN_KEY_PEM', str(key_file.absolute()))
            main.SIGNING_KEY = main.get_signing_key()

            # load a GPG key
            pub_key = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
    
            mDMEZZ6XXxYJKwYBBAHaRw8BAQdAea3323zBNgy12RVKkCWWgfDe5vSLW3R9/6LS
            pqE/hxG0MUdQRyB0ZXN0IGtleSAoT05MWSBGT1IgVEVTVElORykgPG1hcmt1c0B0
            ZXN0Lm9yZz6IkwQTFgoAOxYhBMuek9p7pwAmbyYg1qWXo028DaarBQJlnpdfAhsD
            BQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKWXo028DaarUU8BAOyAmxed
            yWBHajYaEoyn0wfSEGIFVCXatsvcbYpL6hc+AQCrn/t+oC/OqrO4HWPhQDAEgYtW
            9TWOC3A6CYyodYdPD7g4BGWel18SCisGAQQBl1UBBQEBB0DLccDTMTVh0a7Su94Z
            ktDBAzTjYzQ5j2sxKe/OkK2VGQMBCAeIeAQYFgoAIBYhBMuek9p7pwAmbyYg1qWX
            o028DaarBQJlnpdfAhsMAAoJEKWXo028DaarD+EA/0SIgap5bj9FqE+TwVNILLuO
            UiwX/3AQaMi36RJ9oZYKAP9gIkwaL/m0Xu8WQiUNkATCHFsmauptqQw5V8GkSp0l
            Ag==
            =IhBg
            -----END PGP PUBLIC KEY BLOCK-----
            '''

            m.setenv('GPG_KEY_DIR', str(tmp_path.absolute()))
            gpg_pub_key = tmp_path / 'gpg_pub_key.asc'
            gpg_pub_key.write_text(pub_key)

            main.key_fingerprints = main.load_gpg_keys()

            # the server list mock from discord
            target_channels = []

            channel1 = mocker.Mock(spec=nextcord.TextChannel)
            channel1.guild.id = 1111
            channel1.guild.name = "Server 1"
            channel1.id = 110011
            channel1.name = "Channel 1"
            channel1.threads = []
            target_channels.append(channel1)

            channel2 = mocker.Mock(spec=nextcord.TextChannel)
            channel2.guild.id = 1111
            channel2.guild.name = "Server 1"
            channel2.id = 220011
            channel2.name = "Channel 2"
            channel2.threads = []
            target_channels.append(channel2)

            channel3 = mocker.Mock(spec=nextcord.TextChannel)
            channel3.guild.id = 2222
            channel3.guild.name = "Server 2"
            channel3.id = 220022
            channel3.name = "Channel 1"
            channel3.threads = []
            target_channels.append(channel3)

            # with threads
            thread1 = mocker.Mock()
            thread1.name = "Thread 1"
            thread1.id = 121212

            channel4 = mocker.Mock(spec=nextcord.TextChannel)
            channel4.guild.id = 2222
            channel4.guild.name = "Server 2"
            channel4.id = 330022
            channel4.name = "Channel 2"
            channel4.threads = [thread1]
            target_channels.append(channel4)

            channel5 = mocker.Mock(spec=nextcord.VoiceChannel)
            target_channels.append(channel5)

            dt = datetime.datetime.now()
            iso8601_format = dt.isoformat().replace(':', '-').replace('.', '-')

            main.generate_directory_file(target_channels, dt)

            # check if a directory was written
            result_manifest_path = tmp_path / f'{iso8601_format}.dir'
            assert os.path.exists(result_manifest_path)

            # check if a directory seal was written
            result_manifest_path = tmp_path / f'{iso8601_format}.dirseal'
            assert os.path.exists(result_manifest_path)

