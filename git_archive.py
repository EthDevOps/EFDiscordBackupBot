"""
Git Archive Module for Discord Backup Bot

Writes Discord messages to GitHub repositories in a format compatible with
discord-backup-restorer. Runs in parallel with the existing encrypted S3 backup.
"""

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from git import Repo
from git.exc import GitCommandError


class GitArchiveConfig:
    """Load and validate per-server git archive configuration."""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from JSON file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Git archive config not found: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    @property
    def default_branch(self) -> str:
        return self.config.get('default_branch', 'main')

    @property
    def commit_batch_size(self) -> int:
        return self.config.get('commit_batch_size', 50)

    def get_server_config(self, server_id: str) -> Optional[dict]:
        """Get configuration for a specific server."""
        servers = self.config.get('servers', {})
        return servers.get(str(server_id))

    def is_server_enabled(self, server_id: str) -> bool:
        """Check if git archiving is enabled for a server."""
        server_config = self.get_server_config(server_id)
        if server_config is None:
            return False
        return server_config.get('enabled', False)


class GitArchiveManager:
    """Manages git-based archiving of Discord messages."""

    def __init__(self, config: GitArchiveConfig, clone_path: str, github_token: str):
        self.config = config
        self.clone_path = clone_path
        self.github_token = github_token
        self.repos: dict[str, Repo] = {}
        self.message_queues: dict[str, list] = {}  # channel_id -> messages

    def _get_repo_path(self, server_id: str) -> str:
        """Get the local path for a server's repo clone."""
        return os.path.join(self.clone_path, str(server_id))

    def _get_authenticated_url(self, repo_url: str) -> str:
        """Add GitHub token to repo URL for authentication."""
        if repo_url.startswith('https://github.com/'):
            return repo_url.replace(
                'https://github.com/',
                f'https://{self.github_token}@github.com/'
            )
        return repo_url

    def ensure_repo_cloned(self, server_id: str) -> Optional[Repo]:
        """Ensure the repository for a server is cloned and up to date."""
        server_config = self.config.get_server_config(server_id)
        if server_config is None or not server_config.get('enabled', False):
            return None

        repo_path = self._get_repo_path(server_id)
        repo_url = server_config.get('repo_url')
        branch = server_config.get('branch', self.config.default_branch)

        if str(server_id) in self.repos:
            return self.repos[str(server_id)]

        auth_url = self._get_authenticated_url(repo_url)

        if os.path.exists(repo_path):
            # Repo exists, open and pull
            print(f'\t[Git Archive] Opening existing repo at {repo_path}')
            repo = Repo(repo_path)
            try:
                repo.remotes.origin.pull()
            except GitCommandError as e:
                print(f'\t[Git Archive] Warning: Could not pull: {e}')
        else:
            # Clone the repo
            print(f'\t[Git Archive] Cloning {repo_url} to {repo_path}')
            os.makedirs(repo_path, exist_ok=True)
            repo = Repo.clone_from(auth_url, repo_path, branch=branch)

        self.repos[str(server_id)] = repo
        return repo

    def should_archive_channel(self, channel) -> bool:
        """Determine if a channel should be archived based on config."""
        server_id = str(channel.guild.id)
        server_config = self.config.get_server_config(server_id)

        if server_config is None or not server_config.get('enabled', False):
            return False

        # Check excluded channels
        excluded_channels = server_config.get('excluded_channels', [])
        if channel.name in excluded_channels:
            return False

        # Check allowed categories
        allowed_categories = server_config.get('allowed_categories', [])
        if allowed_categories:
            category_name = channel.category.name if channel.category else None
            if category_name not in allowed_categories:
                return False

        return True

    def queue_message(self, backup_msg: dict, channel) -> None:
        """Queue a message for later batch commit."""
        channel_key = f"{backup_msg['server']['id']}_{channel.id}"
        if channel_key not in self.message_queues:
            self.message_queues[channel_key] = []

        self.message_queues[channel_key].append({
            'backup_msg': backup_msg,
            'channel': channel
        })

    def _to_export_format(self, backup_msg: dict, attachments_dir: Path,
                          include_attachments: bool) -> dict:
        """Convert internal backup format to DiscordExportMessage format."""
        export_attachments = []

        if include_attachments:
            for attach in backup_msg.get('attachments', []):
                # Decode base64 content
                content_b64 = attach.get('content', '')
                if content_b64:
                    content_bytes = base64.b64decode(content_b64)
                    # Compute SHA256 hash
                    content_hash = hashlib.sha256(content_bytes).hexdigest()

                    # Write binary file
                    attachments_dir.mkdir(parents=True, exist_ok=True)
                    attachment_path = attachments_dir / f"{content_hash}.bin"
                    if not attachment_path.exists():
                        with open(attachment_path, 'wb') as f:
                            f.write(content_bytes)

                    export_attachments.append({
                        'type': attach.get('type', ''),
                        'origin_name': attach.get('origin_name', ''),
                        'content': content_hash
                    })

        return {
            'author': backup_msg['author']['name'],
            'category': backup_msg.get('category', ''),
            'parent': backup_msg.get('parent', ''),
            'content': backup_msg.get('content', ''),
            'created_at': backup_msg.get('created_at', ''),
            'attachments': export_attachments
        }

    def _get_date_from_iso(self, iso_string: str) -> str:
        """Extract date (YYYY-MM-DD) from ISO timestamp."""
        try:
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
        except (ValueError, AttributeError):
            return datetime.now().strftime('%Y-%m-%d')

    def _write_daily_json(self, json_path: Path, new_messages: list) -> int:
        """
        Write messages to daily JSON file, merging with existing if present.
        Returns the number of new messages added.
        """
        existing_messages = []

        if json_path.exists():
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    existing_messages = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing_messages = []

        # Create a set of existing timestamps for deduplication
        existing_timestamps = {msg.get('created_at') for msg in existing_messages}

        # Add only new messages (dedupe by created_at)
        new_count = 0
        for msg in new_messages:
            if msg.get('created_at') not in existing_timestamps:
                existing_messages.append(msg)
                existing_timestamps.add(msg.get('created_at'))
                new_count += 1

        # Sort all messages by created_at
        existing_messages.sort(key=lambda m: m.get('created_at', ''))

        # Write back
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(existing_messages, f, indent=2, ensure_ascii=False)

        return new_count

    async def flush_and_commit(self, channel) -> None:
        """Flush queued messages and commit to git."""
        channel_key = f"{channel.guild.id}_{channel.id}"
        queued = self.message_queues.pop(channel_key, [])

        if not queued:
            return

        server_id = str(channel.guild.id)
        server_config = self.config.get_server_config(server_id)
        if server_config is None:
            return

        include_attachments = server_config.get('include_attachments', True)

        repo = self.ensure_repo_cloned(server_id)
        if repo is None:
            return

        repo_path = Path(self._get_repo_path(server_id))
        channel_name = channel.name

        # Sanitize channel name for filesystem
        safe_channel_name = "".join(
            c if c.isalnum() or c in '-_' else '_' for c in channel_name
        )

        channel_dir = repo_path / safe_channel_name
        attachments_dir = channel_dir / 'attachments'

        # Group messages by date
        messages_by_date: dict[str, list] = {}
        for item in queued:
            backup_msg = item['backup_msg']
            date_str = self._get_date_from_iso(backup_msg.get('created_at', ''))

            if date_str not in messages_by_date:
                messages_by_date[date_str] = []

            export_msg = self._to_export_format(
                backup_msg, attachments_dir, include_attachments
            )
            messages_by_date[date_str].append(export_msg)

        # Write daily JSON files
        total_new = 0
        date_range = []
        for date_str, messages in messages_by_date.items():
            json_path = channel_dir / f"{date_str}.json"
            new_count = self._write_daily_json(json_path, messages)
            total_new += new_count
            if new_count > 0:
                date_range.append(date_str)

        if total_new == 0:
            print(f'\t[Git Archive] No new messages to commit for #{channel_name}')
            return

        # Stage all changes
        repo.git.add(A=True)

        # Check if there are staged changes
        if not repo.is_dirty(index=True):
            print(f'\t[Git Archive] No changes to commit for #{channel_name}')
            return

        # Create commit message
        date_range.sort()
        if len(date_range) == 1:
            date_info = date_range[0]
        else:
            date_info = f"{date_range[0]} to {date_range[-1]}"

        commit_message = f"Archive {total_new} messages from #{channel_name} ({date_info})"
        print(f'\t[Git Archive] {commit_message}')

        repo.index.commit(commit_message)

        # Push changes
        try:
            repo.remotes.origin.push()
            print(f'\t[Git Archive] Pushed changes for #{channel_name}')
        except GitCommandError as e:
            print(f'\t[Git Archive] Warning: Could not push: {e}')


def is_git_archive_enabled() -> bool:
    """Check if git archiving is globally enabled."""
    return os.getenv('GIT_ARCHIVE_ENABLED') == '1'


def init_git_archive() -> Optional[GitArchiveManager]:
    """Initialize git archive manager if enabled."""
    if not is_git_archive_enabled():
        return None

    config_path = os.getenv('GIT_ARCHIVE_CONFIG_PATH')
    if config_path is None:
        print('[Git Archive] Warning: GIT_ARCHIVE_ENABLED=1 but GIT_ARCHIVE_CONFIG_PATH not set')
        return None

    clone_path = os.getenv('GIT_ARCHIVE_CLONE_PATH')
    if clone_path is None:
        print('[Git Archive] Warning: GIT_ARCHIVE_ENABLED=1 but GIT_ARCHIVE_CLONE_PATH not set')
        return None

    github_token = os.getenv('GITHUB_TOKEN')
    if github_token is None:
        print('[Git Archive] Warning: GIT_ARCHIVE_ENABLED=1 but GITHUB_TOKEN not set')
        return None

    try:
        config = GitArchiveConfig(config_path)
        print('[Git Archive] Initialized successfully')
        return GitArchiveManager(config, clone_path, github_token)
    except FileNotFoundError as e:
        print(f'[Git Archive] Warning: {e}')
        return None
    except json.JSONDecodeError as e:
        print(f'[Git Archive] Warning: Invalid config JSON: {e}')
        return None
