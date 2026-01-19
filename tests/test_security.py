"""Tests for security module."""

import pytest
from pathlib import Path
from microsoft_mcp.security import validate_read_path, validate_write_path


class TestValidateReadPath:
    """Tests for validate_read_path function."""

    def test_allows_normal_file(self, tmp_path: Path) -> None:
        """Normal files should be allowed."""
        test_file = tmp_path / "document.txt"
        test_file.write_text("content")
        result = validate_read_path(str(test_file))
        assert result == test_file

    def test_blocks_ssh_directory(self) -> None:
        """SSH directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.ssh/id_rsa")

    def test_blocks_aws_credentials(self) -> None:
        """AWS credentials should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.aws/credentials")

    def test_blocks_gnupg_directory(self) -> None:
        """GnuPG directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.gnupg/private-keys-v1.d/key.key")

    def test_blocks_kube_config(self) -> None:
        """Kubernetes config should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.kube/config")

    def test_blocks_docker_config(self) -> None:
        """Docker config should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.docker/config.json")

    def test_blocks_gcloud_credentials(self) -> None:
        """GCloud credentials should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.config/gcloud/credentials.db")

    def test_blocks_npmrc(self) -> None:
        """npmrc should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_read_path("~/.npmrc")

    def test_blocks_pypirc(self) -> None:
        """pypirc should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_read_path("~/.pypirc")

    def test_blocks_netrc(self) -> None:
        """netrc should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_read_path("~/.netrc")

    def test_blocks_pem_files(self) -> None:
        """PEM files should be blocked."""
        with pytest.raises(ValueError, match="key/certificate"):
            validate_read_path("/tmp/server.pem")

    def test_blocks_key_files(self) -> None:
        """Key files should be blocked."""
        with pytest.raises(ValueError, match="key/certificate"):
            validate_read_path("/tmp/private.key")

    def test_blocks_p12_files(self) -> None:
        """P12 files should be blocked."""
        with pytest.raises(ValueError, match="key/certificate"):
            validate_read_path("/tmp/cert.p12")

    def test_blocks_pfx_files(self) -> None:
        """PFX files should be blocked."""
        with pytest.raises(ValueError, match="key/certificate"):
            validate_read_path("/tmp/cert.pfx")

    def test_blocks_env_file(self) -> None:
        """Env files should be blocked."""
        with pytest.raises(ValueError, match="environment files"):
            validate_read_path("/project/.env")

    def test_blocks_env_local(self) -> None:
        """Env.local files should be blocked."""
        with pytest.raises(ValueError, match="environment files"):
            validate_read_path("/project/.env.local")

    def test_blocks_env_production(self) -> None:
        """Env.production files should be blocked."""
        with pytest.raises(ValueError, match="environment files"):
            validate_read_path("/project/.env.production")

    def test_blocks_credentials_in_name(self) -> None:
        """Files with 'credentials' in name should be blocked."""
        with pytest.raises(ValueError, match="sensitive names"):
            validate_read_path("/tmp/db_credentials.json")

    def test_blocks_secret_in_name(self) -> None:
        """Files with 'secret' in name should be blocked."""
        with pytest.raises(ValueError, match="sensitive names"):
            validate_read_path("/tmp/client_secret.json")

    def test_blocks_token_in_name(self) -> None:
        """Files with 'token' in name should be blocked."""
        with pytest.raises(ValueError, match="sensitive names"):
            validate_read_path("/tmp/access_token.txt")

    def test_blocks_password_in_name(self) -> None:
        """Files with 'password' in name should be blocked."""
        with pytest.raises(ValueError, match="sensitive names"):
            validate_read_path("/tmp/password_list.txt")

    def test_blocks_token_cache(self) -> None:
        """Token cache file should be blocked."""
        with pytest.raises(ValueError, match="token cache"):
            validate_read_path("~/.microsoft_mcp_token_cache.json")

    def test_blocks_etc_passwd(self) -> None:
        """System passwd file should be blocked."""
        with pytest.raises(ValueError, match="system files"):
            validate_read_path("/etc/passwd")

    def test_blocks_etc_shadow(self) -> None:
        """System shadow file should be blocked."""
        with pytest.raises(ValueError, match="system files"):
            validate_read_path("/etc/shadow")

    def test_blocks_etc_sudoers(self) -> None:
        """System sudoers file should be blocked."""
        with pytest.raises(ValueError, match="system files"):
            validate_read_path("/etc/sudoers")

    def test_blocks_path_traversal(self) -> None:
        """Path traversal should be blocked."""
        with pytest.raises(ValueError, match="traversal"):
            validate_read_path("/tmp/../etc/passwd")

    def test_blocks_path_traversal_in_middle(self) -> None:
        """Path traversal in middle should be blocked."""
        with pytest.raises(ValueError, match="traversal"):
            validate_read_path("/home/user/../root/.ssh/id_rsa")

    def test_blocks_bash_history(self) -> None:
        """Bash history should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_read_path("~/.bash_history")

    def test_blocks_zsh_history(self) -> None:
        """Zsh history should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_read_path("~/.zsh_history")

    def test_blocks_credentials_case_insensitive(self) -> None:
        """Credentials pattern should be case-insensitive."""
        with pytest.raises(ValueError, match="sensitive names"):
            validate_read_path("/tmp/AWS_CREDENTIALS.json")

    def test_blocks_env_case_insensitive(self) -> None:
        """Env file pattern should be case-insensitive."""
        with pytest.raises(ValueError, match="environment files"):
            validate_read_path("/project/.ENV")

    def test_blocks_password_store(self) -> None:
        """Password store directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_read_path("~/.password-store/email.gpg")


class TestValidateWritePath:
    """Tests for validate_write_path function."""

    def test_allows_normal_file(self, tmp_path: Path) -> None:
        """Normal files should be allowed."""
        test_file = tmp_path / "output.txt"
        result = validate_write_path(str(test_file))
        assert result == test_file

    def test_blocks_bashrc(self) -> None:
        """Bashrc should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("~/.bashrc")

    def test_blocks_zshrc(self) -> None:
        """Zshrc should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("~/.zshrc")

    def test_blocks_profile(self) -> None:
        """Profile should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("~/.profile")

    def test_blocks_bash_profile(self) -> None:
        """Bash profile should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("~/.bash_profile")

    def test_blocks_ssh_directory(self) -> None:
        """SSH directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.ssh/authorized_keys")

    def test_blocks_gnupg_directory(self) -> None:
        """GnuPG directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.gnupg/trustdb.gpg")

    def test_blocks_aws_directory(self) -> None:
        """AWS directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.aws/credentials")

    def test_blocks_kube_directory(self) -> None:
        """Kube directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.kube/config")

    def test_blocks_systemd_directory(self) -> None:
        """Systemd user directory should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.config/systemd/user/malicious.service")

    def test_blocks_authorized_keys_anywhere(self) -> None:
        """Authorized keys file should be blocked anywhere."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("/tmp/authorized_keys")

    def test_blocks_known_hosts_anywhere(self) -> None:
        """Known hosts file should be blocked anywhere."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("/tmp/known_hosts")

    def test_blocks_crontab_anywhere(self) -> None:
        """Crontab file should be blocked anywhere."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("/tmp/crontab")

    def test_blocks_path_traversal(self) -> None:
        """Path traversal should be blocked."""
        with pytest.raises(ValueError, match="traversal"):
            validate_write_path("/tmp/../home/user/.bashrc")

    def test_blocks_launch_agents(self) -> None:
        """macOS LaunchAgents should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/Library/LaunchAgents/com.malicious.plist")

    def test_blocks_zprofile(self) -> None:
        """Zprofile should be blocked."""
        with pytest.raises(ValueError, match="sensitive file"):
            validate_write_path("~/.zprofile")

    def test_blocks_autostart(self) -> None:
        """Linux autostart should be blocked."""
        with pytest.raises(ValueError, match="sensitive directory"):
            validate_write_path("~/.config/autostart/malicious.desktop")
