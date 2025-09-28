#!/usr/bin/env python3
"""
RAID Security Assessment Framework Setup
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements from requirements.txt
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="raid-security-framework",
    version="0.1.0",
    author="RAID Development Team",
    author_email="dev@raid-framework.org",
    description="Agentic, containerized security assessment framework with MCP server",
    long_description=read_readme() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/raid-framework/raid",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Framework :: FastAPI",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.12.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.7.0",
            "pre-commit>=3.5.0",
        ],
        "security": [
            "bandit>=1.7.5",
            "safety>=2.3.5",
            "semgrep>=1.45.0",
        ],
        "docs": [
            "mkdocs>=1.5.3",
            "mkdocs-material>=9.4.6",
            "mkdocstrings[python]>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "raid=controller.main:main",
        ],
    },
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.md", "*.txt"],
    },
    include_package_data=True,
    keywords="security assessment pentesting mcp container framework",
    project_urls={
        "Bug Reports": "https://github.com/raid-framework/raid/issues",
        "Source": "https://github.com/raid-framework/raid",
        "Documentation": "https://docs.raid-framework.org",
    },
)