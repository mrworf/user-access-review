#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import logging
import os
import getpass
import socket
from datetime import datetime
import time

# Make git functionality optional
try:
    from git import Repo, InvalidGitRepositoryError, NoSuchPathError
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

class Receipt:
    """Class to track the audit trail of a run"""
    
    def __init__(self):
        self.timestamp = datetime.now()
        self.timezone = time.tzname[0] if time.daylight == 0 else time.tzname[1]
        self.user = getpass.getuser()
        self.files = {}  # filename -> {'hash': sha256sum, 'description': str}
        self.commit = self._get_commit_info() if GIT_AVAILABLE else None
        self.hostname = self._get_hostname()
        self.ip_address = self._get_ip_address()

    def _get_hostname(self):
        """Get the computer's hostname
        
        Returns:
            Hostname string or None if unavailable
        """
        try:
            return socket.gethostname()
        except Exception as e:
            logging.warning(f"Could not get hostname: {e}")
            return None

    def _get_ip_address(self):
        """Get the computer's IP address
        
        Returns:
            IP address string or None if unavailable
        """
        try:
            # Try to get the IP address that would be used to connect to the internet
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's DNS server
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logging.warning(f"Could not get IP address: {e}")
            return None

    def _get_commit_info(self):
        """Get git commit information if available
        
        Returns:
            Dictionary with commit info or None if not in git repo
        """
        try:
            repo = Repo(os.getcwd(), search_parent_directories=True)
            return {
                'hash': repo.head.commit.hexsha,
                'branch': repo.active_branch.name
            }
        except (InvalidGitRepositoryError, NoSuchPathError):
            return None

    def audit_file(self, filename, description):
        """Add a file to the audit trail
        
        Args:
            filename: Path to the file
            description: Description of the file's purpose
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File {filename} not found")
            
        # Get file stats
        stats = os.stat(filename)
        mtime = datetime.fromtimestamp(stats.st_mtime)
            
        # Calculate SHA256 hash
        with open(filename, 'rb') as f:
            content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()
            
        # Store file info
        self.files[filename] = {
            'hash': file_hash,
            'description': description,
            'size': len(content),
            'modified': mtime
        }

    def save(self, filename):
        """Save the receipt to a human-readable text file
        
        Args:
            filename: Name of the file to save to
            
        Returns:
            SHA-256 hash of the receipt content
        """
        # Generate human-readable content
        lines = [
            "User Access Review Receipt",
            "========================",
            "",
            f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} {self.timezone}",
            f"User: {self.user}",
        ]

        # Add system information
        if self.hostname:
            lines.append(f"Hostname: {self.hostname}")
        if self.ip_address:
            lines.append(f"IP Address: {self.ip_address}")
        lines.append("")

        # Add git information if available
        if self.commit:
            lines.extend([
                "Git Information",
                "--------------",
                f"Branch: {self.commit['branch']}",
                f"Commit: {self.commit['hash']}",
                ""
            ])

        # Add file information
        lines.extend([
            "Processed Files",
            "--------------"
        ])
        
        for file_path, info in self.files.items():
            lines.extend([
                f"File: {file_path}",
                f"Description: {info['description']}",
                f"Size: {info['size']} bytes",
                f"Modified: {info['modified'].strftime('%Y-%m-%d %H:%M:%S')} {self.timezone}",
                f"SHA256: {info['hash']}",
                ""
            ])

        # Join lines and encode
        content = "\n".join(lines).encode('utf-8')
        
        try:
            # Write to file
            with open(filename, 'wb') as f:
                f.write(content)
        except Exception as e:
            logging.error(f"Error saving receipt to {filename}: {e}")
            raise
            
        # Calculate and return hash
        return hashlib.sha256(content).hexdigest()
